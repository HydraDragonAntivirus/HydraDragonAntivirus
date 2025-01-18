rule Linux_Golang_Ransomware: linux ransomware golang
{
    meta:
        author = "Adam M. Swanda"
        reference = "https://www.fortinet.com/blog/threat-research/new-golang-ransomware-targeting-linux-systems.html"
    
    strings:
        $str001 = "1) Email: fullofdeep@protonmail.com" ascii fullword
        $str002 = "https://ipapi.com/json/idna:" ascii
        $str003 = "%s.encrypted.localhost" ascii
        $str004 = ".local.onion" ascii
        $str005 = "DO NOT TRY TO DO SOMETHING TO YOUR FILES YOU WILL BRAKE YOUR DATA" ascii fullword
        $str006 = "4.We can decrypt few files in quality the evidence that we have the decoder." ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and all of them
}
rule ACBackdoor_ELF: linux malware backdoor
{
    meta:
        author = "Adam M. Swanda"
        date = "Nov 2019"
        reference = "https://www.intezer.com/blog-acbackdoor-analysis-of-a-new-multiplatform-backdoor/"

    strings:
        $ua_str = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" ascii fullword
        $header1 = "Access-Control:" ascii fullword
        $header2 = "X-Access" ascii

        $initd = "/etc/init.d/update-notifier" ascii fullword
        $str001 = "#!/bin/sh -e" ascii fullword
        $str002 = "### BEGIN INIT INFO" ascii fullword
        $str003 = "# Provides:          update-notifier" ascii fullword
        $str004 = "# Required-Start:    $local_fs" ascii fullword
        $str005 = "# Required-Stop:" ascii fullword
        $str006 = "# Default-Start:     S" ascii fullword
        $str007 = "# Default-Stop:" ascii fullword
        $str008 = "### END INIT INFO" ascii fullword
        $str010 = "  *) echo \"Usage: $0 {start|stop|restart|force-reload}\" >&2; ;;" ascii fullword
        $str011 = "esac" ascii fullword
        $str012 = "[ -x /usr/local/bin/update-notifier ] \\" ascii fullword
        $str013 = "    && exec /usr/local/bin/update-notifier" ascii fullword
        $rcd01 = "/etc/rc2.d/S01update-notifier" ascii fullword
        $rcd02 = "/etc/rc3.d/S01update-notifier" ascii fullword
        $rcd03 = "/etc/rc5.d/S01update-notifier" ascii fullword

    condition:
        /* trigger = '{7f 45 4c 46}' - ELF magic bytes */
        (uint32be(0x0) == 0x7f454c46)
        and
        (
            ($ua_str and all of ($header*) and $initd and all of ($rcd*))
            or
            (
                $ua_str and all of ($header*) and 10 of ($str*)
            )
        )
}
rule APT32_KerrDown: apt apt32 winmalware downloader
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-08"
        Note = "List of samples used to create rule at end of file as block comment"

    strings:
        $hijack = "DllHijack.dll" ascii fullword
        $fmain = "FMain" ascii fullword
        $gfids = ".gfids" ascii fullword
        $sec01 = ".xdata$x" ascii fullword
        $sec02 = ".rdata$zzzdbg" ascii fullword
        $sec03 = ".rdata$sxdata" ascii fullword

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

/*
    Matched sample set:

        4a0309d8043e8acd7cb5c7cfca95223afe9c15a1c34578643b49ded4b786506b
        4b431af677041dae3c988fcc901ac8ec6e74c6e1467787bf099c4abd658be5be
        4bc00f7d638e042da764e8648c03c0db46700599dd4f08d117e3e9e8b538519b
        4e2f8f104e6cd07508c5b7d49737a1db5eeba910adfdb4c19442a7699dc78cfc
        4e791f2511c9bd3c63c8e37aa6625d8b590054de9e1cca13a7be2630bc2af9ce
        539e8a53db3f858914cfe0d2132f11de34a691391ba71673a8b1e61367a963c7
        53cd92f37ffd0822cc644717363ba239d75c6d9af0fa305339eaf34077edd22d
        53efaac9244c24fab58216a907783748d48cb32dbdc2f1f6fb672bd49f12be4c
        5c18c3e6f7ac0d0ac2b5fa9a6435ee90d6bd77995f85bed9e948097891d42ca2
        5f0db8216314da1f128b883b918e5ac722202a2ae0c4d0bf1c5da5914a66778e
        6010d44cdca58cdec4559040e08798e7b28b9434bda940da0a670c93c84e33cd
        60b65ebb921dca4762aef427181775d10bbffc30617d777102762ab7913a5aa1
        6146aedfe47597606fb4b05458ec4b99d4e1042da7dc974fa33a57e282cd7349
        6245b74b1cc830ed95cb630192c704da66600b90a331d9e6db70210acb6c7dfa
        67cd191eb2322bf8b0f04a63a9e7cb7bc52fb4a4444fcb8fed2963884aede3aa
        68f77119eae5e9d2404376f2d87e71e4ab554c026e362c57313e5881005ae79e
        69e679daaaff3832c39671bf2b813b5530a70fb763d381f9a6e22e3bc493c8a9
        6fb397e90f72783adec279434fe805c732ddb7d1d6aa72f19e91a1bf585e1ea5
        70db041fb5aadb63c1b8ae57ba2699baa0086e9b011219dcebcccbf632017992
        7673f5468ba3cf01500f6bb6a19ce7208c8b6fc24f1a3a388eca491bc25cd9cd
        77805a46f73e118ae2428f8c22ba28f79f7c60aeb6305d41c0bf3ebb9ce70f94
        788265447391189ffc1956ebfec990dc051b56f506402d43cd1d4de96709c082
        7be613237b57fbc3cb83d001efadeed9936a2f519c514ab80de8285bdc5a666c
        7dbb7fab4782f5e3b0c416c05114f2a51f12643805d5f3d0cd80d32272f2731a
        7ec77e643d8d7cc18cc67c123feceed91d10db1cc9fa0c49164cba35bb1da987
        860f165c2240f2a83eb30c412755e5a025e25961ce4633683f5bc22f6a24ddb6
        89759e56d5c23085e47d2be2ce4ad4484dfdd4204044a78671ed434cec19b693
        8b7fb1cd5c09f7ec57ccc0c4261c0b4df0604962556a1d401b9cbfd750df60ba
        8d6e31c95d649c08cdc2f82085298173d03c03afe02f0dacb66dd3560149184f
        942d763604d0aefdff10ce095f806195f351124a8433c96f5590d89d809a562f
        98a5f30699564e6d9f74e737a611246262907b9e91b90348f7de53eb4cf32665
        9e6011d6380207e2bf5105cde3d48e412db565b92cdc1b3c6aa15bd7bd4b099f
        a106e0a6b7cc30b161e5ea0b1ec0f28ab89c2e1eb7ba2d5d409ddbabc3b037e6
        a2b905c26e2b92e63de85d83e280249258cb21f300d8c4a3a6bdb488676e9bcf
        a4a86e96f95f395fcf0ceb6a74a2564f4ba7adbe1b40cc702b054427327a0399
        a8192656dd1db0be4cec9d03b4d10e0529d9c52c899eda8d8e72698acfb61419
        a8f776bd3a9593e963b567ce790033fec2804ea0afb40a92d40e21d8f33d066f
        b4966f8febdba6b2d674afffc65b1df11e7565acbd4517f1e5b9b36a8c6a16ed
        bb25f1a73d095d57b2c8c9ac6780e4d412ddf3d9eef84a54903cc8e4eaefc335
        bc82bce004afb6424e9d9f9fc04a84f58edf859c4029eda08f7309dbeec67696
        c30198e0b0e470d4ac8821bd14bb754466e7974f1c20be8b300961e9e89ed1ea
        caabc45e59820a4349db13f337063eddede8a0847ae313d89a800f241d8556c8
        d3ef6643ad529d43a7ec313b52c8396dc52c4daad688360eb207ee91a1caf7b2
        e3c818052237bb4bb061290ab5e2a55c3852c8a3fef16436b1197e8b17de2e18
        e56ffcf5df2afd6b151c24ddfe7cd450f9208f59b5731991b926af0dce24285a
        e8704bf6525c90e0f5664f400c3bf8ff5da565080a52126e0e6a62869157dfe3
        e8a454cd8b57a243f0abeec6945c9b10616cfdcc4abfb4c618bfc469d026d537
        eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b
        ead0f3e6f0ca16b283f09526d09e8e8cba687dab642f0e102e5487cb565bf475
        f011a136996fa53fdbde944da0908da446b9532307a35c44ed08241b5e602cc9
        f2a2f4fa2ed5b2a94720a4661937da97ab21aa198a5f8c83bb6895aa2c398d22
        f62f21ee7e642f272b881827b45ceb643c999a742e1d3eac13d1ba014d1e7f67
        f9f0973dc74716b75291f5a9b2d59b08500882563011d1def2b8d0b1b9bbb8ae
*/
rule APT32_Ratsnif: apt32 trojan winmalware
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-18"

    strings:
        $pdb0 = "X:\\Project\\BotFrame\\Debug\\Client.pdb" ascii fullword

        $str1 = "LastIP" ascii fullword
        $str2 = "LastOnline" ascii fullword
        $str3 = "LoaderType" ascii fullword
        $str4 = "Payload" ascii fullword
        $str5 = "PayloadFile" ascii fullword
        $str6 = "ClientCommand" ascii fullword
        $str7 = "ClientId" ascii fullword
        $str8 = "UserAdmin" ascii fullword
        $str9 = "User" ascii fullword
        $str10 = "Password" ascii fullword
        $str11 = "Access" ascii fullword
        $str12 = "CreateDate" ascii fullword
        $str13 = "CreateBy" ascii fullword
        $str14 = "UserName" ascii fullword
        $str15 = "ComputerName" ascii fullword
        $str16 = "Domain" ascii fullword
        $str17 = "OSType" ascii fullword
        $str18 = "OSArch" ascii fullword
        $str19 = "OSVer" ascii fullword
        $str20 = "InstallDate" ascii fullword
        $str21 = "LastLoadCommandID" ascii fullword
        $str22 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36" ascii fullword
        $str25 = "#########################Program starting up#########################" ascii fullword
        $str26 = "Stop poison" ascii fullword
        $str27 = "Shell:" ascii fullword
        $str28 = "shell" ascii fullword
        $str29 = "Select http redirect domain:" ascii fullword
        $str30 = "HTTP redirect add file extension:" ascii fullword
        $str32 = "exIp" ascii fullword
        $str33 = "Start Poison" ascii fullword
        $str34 = "vicIP" ascii fullword
        $str35 = "Insert JSTag" ascii fullword
        $str36 = "devIp" ascii fullword
        $str37 = "TransmitTcp" ascii fullword
        $str38 = "Remove poison IP: %s" ascii fullword
        $str39 = "Remove my ip or gateway ip: %s" ascii fullword

        $cnc0 = "/cl_client_online.php" ascii fullword
        $cnc1 = "/cl_client_cmd.php" ascii fullword
        $cnc2 = "/cl_client_cmd_res.php" ascii fullword
        $cnc3 = "/cl_client_file_download.php" ascii fullword
        $cnc4 = "/ad_file_download.php" ascii fullword
        $cnc5 = "/cl_client_file_upload.php" ascii fullword
        $cnc6 = "/cl_client_logs.php" ascii fullword

    condition:
        (uint16(0) == 0x5a4d)
        and
        (
            (10 of ($str*) and 3 of ($cnc*))
            or
            (3 of ($cnc*) and $pdb0)
        )
}
rule APT34_LONGWATCH: apt34 winmalware keylogger
{
    meta:
        Description = "APT34 Keylogger"
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $log = "c:\\windows\\temp\\log.txt" ascii fullword
        $clipboard = "---------------CLIPBOARD------------" ascii fullword

        $func0 = "\"Main Invoked.\"" ascii fullword
        $func1 = "\"Main Returned.\"" ascii fullword

        $logger3 = ">---------------------------------------------------" ascii fullword
        $logger4 = "[ENTER]" ascii fullword
        $logger5 = "[CapsLock]" ascii fullword
        $logger6 = "[CRTL]" ascii fullword
        $logger7 = "[PAGE_UP]" ascii fullword
        $logger8 = "[PAGE_DOWN]" ascii fullword
        $logger9 = "[HOME]" ascii fullword
        $logger10 = "[LEFT]" ascii fullword
        $logger11 = "[RIGHT]" ascii fullword
        $logger12 = "[DOWN]" ascii fullword
        $logger13 = "[PRINT]" ascii fullword
        $logger14 = "[PRINT SCREEN]" ascii fullword
        $logger15 = "[INSERT]" ascii fullword
        $logger16 = "[SLEEP]" ascii fullword
        $logger17 = "[PAUSE]" ascii fullword
        $logger18 = "[TAB]" ascii fullword
        $logger19 = "[ESC]" ascii fullword
        $logger20 = "[DEL]" ascii fullword
        $logger21 = "[ALT]" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        $log
        and
        all of ($func*)
        and
        all of ($logger*)
        and $clipboard
}
rule APT34_PICKPOCKET: apt apt34 infostealer winmalware
{
   meta:
      Description = "Detects the PICKPOCKET malware used by APT34, a browser credential-theft tool identified by FireEye in May 2018"
      Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

   strings:
      $s1 = "SELECT * FROM moz_logins;" ascii fullword
      $s2 = "\\nss3.dll" ascii fullword
      $s3 = "SELECT * FROM logins;" ascii fullword
      $s4 = "| %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');" ascii fullword
      $s5 = "\\Login Data" ascii fullword
      $s6 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii fullword
      $s7 = "Login Data" ascii fullword
      $s8 = "encryptedUsernamencryptedPasswor" ascii fullword
      $s10 = "%s\\Mozilla\\Firefox\\%s" ascii fullword
      $s11 = "encryptedUsername" ascii fullword
      $s12 = "2013-12-06 14:53:30 27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii fullword // SQLITE_SOURCE_ID
      $s13 = "27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii
      $s15 = "= 'table' AND name!='sqlite_sequence'   AND coalesce(rootpage,1)>0" ascii fullword
      $s18 = "[*] FireFox :" fullword wide
      $s19 = "[*] Chrome :" fullword wide
      $s20 = "username_value" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and 
      (
         8 of them or all of them
      )
}
rule APT34_VALUEVAULT: apt34 infostealer winmalware
{
    meta:
        Description= "Information stealing malware used by APT34, written in Go."
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $fsociety = "fsociety.dat" ascii

        $powershell = "New-Object -ComObject Shell.Application" ascii

        $gobuild = "Go build ID: " ascii

        $gopath01 = "browsers-password-cracker" ascii nocase
        $gopath02 = "main.go" ascii nocase
        $gopath03 = "mozilla.go" ascii nocase
        $gopath04 = "ie.go" ascii nocase
        // main.go, mozilla.go, ie.go, etc etc... this should probably be a regex but this works too i guess :|

        // some function names
        $str1 = "main.Decrypt" ascii fullword
        $str3 = "main.NewBlob" ascii fullword
        $str4 = "main.CheckFileExist" ascii fullword
        $str5 = "main.CopyFileToDirectory" ascii fullword
        $str6 = "main.CrackChromeBased" ascii fullword
        $str7 = "main.CrackIE" ascii fullword
        $str8 = "main.decipherPassword" ascii fullword
        $str9 = "main.DecodeUTF16" ascii fullword
        $str10 = "main.getHashTable" ascii fullword
        $str11 = "main.getHistory" ascii fullword
        $str12 = "main.getHistoryWithPowerShell" ascii fullword
        $str13 = "main.getHistoryFromRegistery" ascii fullword
        $str14 = "main.main" ascii fullword
        $str15 = "main.DecryptAESFromBase64" ascii fullword
        $str16 = "main.DecryptAES" ascii fullword

        // typo of Mozilla is intentional
        $str17 = "main.CrackMozila" ascii fullword
        $str18 = "main.decodeLoginData" ascii fullword
        $str19 = "main.decrypt" ascii fullword
        $str20 = "main.removePadding" ascii fullword
        $str21 = "main.getLoginData" ascii fullword
        $str22 = "main.isMasterPasswordCorrect" ascii fullword
        $str23 = "main.decrypt3DES" ascii fullword
        $str24 = "main.getKey" ascii fullword
        $str25 = "main.manageMasterPassword" ascii fullword
        $str26 = "main.getFirefoxProfiles" ascii fullword
        $str27 = "main._Cfunc_DumpVault" ascii fullword
        $str28 = "main.CrackIEandEdgeNew" ascii fullword
        $str29 = "main.init.ializers" ascii fullword
        $str30 = "main.init" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (10 of ($str*) and 3 of ($gopath*))
            or
            ($fsociety and $powershell and $gobuild)
            or
            ($fsociety and 10 of ($str*))
        )
}
rule AveMaria_WarZone: avemaria warzone winmalware infostealer
{

    meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
      $str2 = "MsgBox.exe" wide fullword
      $str4 = "\\System32\\cmd.exe" wide fullword
      $str6 = "Ave_Maria" wide
      $str7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii fullword
      $str8 = "SMTP Password" wide fullword
      $str11 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide fullword
      $str12 = "\\sqlmap.dll" wide fullword
      $str14 = "SELECT * FROM logins" ascii fullword
      $str16 = "Elevation:Administrator!new" wide
      $str17 = "/n:%temp%" ascii wide

   condition:
      (
        uint16(0) == 0x5a4d and filesize < 400KB
      )
      and
      (
        5 of ($str*)
        or all of them
      )
}

rule CrescentCore_DMG: installer macosmalware
{

    meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $header0 = "__PAGEZERO" ascii
      $header1 = "__TEXT" ascii

      $path0 = "/Users/mehdi/Desktop/RED MOON/Project/WaningCrescent/WaningCrescent/" ascii

      $install0 = ".app\" /Applications" ascii fullword
      $install1 = "open \"/Applications/" ascii fullword

      $str1 = /Flash_Player\dVirusMp/ ascii
      $str2 = /Flash_Player\dAntivirus33/ ascii
      $str3 = /Flash_Player\d{2}Armageddon/ ascii
      $str4 = /Flash_Player\d{2}Armageddon\w\dapocalypsyy/
      $str5 = /Flash_Player\d{2}Armageddon\w\ddoomsdayyy/

      $str6 = /SearchModel\w\dbrowser/
      $str8 = /SearchModel\w\dcountry/
      $str9 = /SearchModel\w\dhomepage/
      $str10 = /SearchModel\w\dthankyou/
      $str11 = /SearchModel\w\dinterrupt/
      $str12 = /SearchModel\w\dsearch/
      $str13 = /SearchModel\w\dsuccess/
      $str14 = /SearchModel\w\d{2}carrierURL/

   condition:
      (
        uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or
        uint32(0) == 0xbebafeca
      ) and $header0 and $header1
      and
      (
        ($path0 and (any of ($install*)))
        or (5 of ($str*))
      )
      or all of them
}

rule Dacls_Trojan_Linux
{
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

        $str00 = "{\"result\":\"ok\"}" ascii fullword
        $str01 = "SCAN  %s  %d.%d.%d.%d %d" ascii fullword
        $str02 = "/var/run/init.pid" ascii fullword
        $str03 = "/flash/bin/mountd" ascii fullword
        $str04 = "Name:" ascii fullword
        $str05 = "Uid:" ascii fullword
        $str06 = "Gid:" ascii fullword
        $str08 = "PPid:" ascii fullword
        $str09 = "session_id" ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and
        (
            (all of ($cls*))

            or

            (all of ($str*))

        )
}
rule Dacls_Trojan_Windows
{
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $fext00 = ".exe" ascii wide
        $fext01 = ".cmd" ascii wide
        $fext02 = ".bat" ascii wide
        $fext03 = ".com" ascii wide

        $str00 = "Software\\mthjk" ascii wide
        $str01 = "WindowsNT.dll" ascii fullword
        $str02 = "GET %s HTTP/1.1" ascii fullword
        $str03 = "content-length:" ascii fullword
        $str04 = "Connection: keep-alive" ascii fullword

        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

    condition:
        (uint16(0) == 0x5a4d)
        and
        (
            (all of ($cls*))
            or
            (all of ($fext*) and all of ($str*))
        )
}
rule DNSpionage: apt dnschanger
{
   meta:
      Description = "Attempts to detect DNSpionage PE samples"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $x00 = "/Loginnn?id=" fullword ascii
      $hdr0 = "Content-Disposition: fo" fullword ascii
      $hdr1 = "Content-Type: multi" fullword ascii
      $ua0 = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36" fullword ascii
      $ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" fullword ascii

      $str0 = "send command result error! status code is: " fullword ascii
      $str1 = "uploading command result form" fullword ascii
      $str2 = "log.txt" fullword ascii
      $str3 = "http host not found in config!" fullword ascii
      $str4 = "send command result" fullword ascii
      $str5 = "download error. status code: " fullword ascii
      $str6 = "get command with dns" fullword ascii
      $str7 = "dns host not found in config!" fullword ascii
      $str8 = "command result is: " fullword ascii
      $str9 = "command result size: " fullword ascii
      $str10 = "connection type not found in config!" fullword ascii
      $str11 = "commands: " fullword ascii
      $str12 = "command is: " fullword ascii
      $str13 = "port not found in config!" fullword ascii
      $str14 = "download filename not found! " fullword ascii
      $str15 = "base64 key not found in config!" fullword ascii
      $str16 = "download filename is: " fullword ascii
      $str17 = "config json is not valid" fullword ascii
      $str18 = "config file will be changed from server!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and (
            (
               5 of ($str*)
            )
            or
            (
               $x00 and (1 of ($hdr*)) and 1 of ($ua*)
            )
      )
}

rule EvilGnome_Linux: infostealer linuxmalware
{
    meta:
        Description = "Detects the EvilGnome backdoor malware designed for Linux desktops, which disguises itself as a Gnome extension."
        Reference = "https://www.intezer.com/blog-evilgnome-rare-malware-spying-on-linux-desktop-users/"

    strings:

        $ftype0 = ".doc" ascii fullword
        $ftype1 = ".docx" ascii fullword
        $ftype2 = ".pdf" ascii fullword
        $ftype3 = ".rtf" ascii fullword

        $cpp0  = "_GLOBAL__sub_I_application.cpp" ascii
        $cpp1  = "_GLOBAL__sub_I_shooterPing.cpp" ascii
        $cpp2  = "_GLOBAL__sub_I_packetBase.cpp" ascii
        $cpp3  = "_GLOBAL__sub_I_parameters.cpp" ascii
        $cpp4  = "_GLOBAL__sub_I_session.cpp" ascii
        $cpp5  = "_GLOBAL__sub_I_packet.cpp" ascii
        $cpp6  = "_GLOBAL__sub_I_rc5.cpp" ascii
        $cpp7  = "shooterImage.cpp" ascii
        $cpp8  = "shooterSound.cpp" ascii
        $cpp9  = "shooterFile.cpp" ascii
        $cpp10  = "../session.cpp" ascii
        $cpp12 = "shooterKey.cpp" ascii
        $cpp13  = "tcpSocket.cpp" ascii
        $cpp14  = "shooter.cpp" ascii
        $cpp15  = "logger.cpp" ascii
        $cpp16  = "engine.cpp" ascii
        $cpp17 = "main.cpp" ascii

        $path0 = ".lib" ascii fullword
        $path1  = "opt" ascii fullword
        $path2  = "proc" ascii fullword
        $path3  = "root" ascii fullword
        $path4  = "run" ascii fullword
        $path5  = "sbin" ascii fullword
        $path6  = "snap" ascii fullword
        $path7  = "srv" ascii fullword
        $path8  = "sys" ascii fullword
        $path9  = "tmp" ascii fullword
        $path10  = "usr" ascii fullword
        $path11  = "boot" ascii fullword
        $path12  = "var" ascii fullword
        $path13  = "cdrom" ascii fullword
        $path14  = "dev" ascii fullword
        $path15  = "etc" ascii fullword
        $path16 = "lib" ascii fullword
        $path17  = "lib32" ascii fullword
        $path18  = "lib64" ascii fullword
        $path19  = "lost+found" ascii fullword

    condition:
        (uint32be(0x0) == 0x7f454c46)
        and
        10 of ($cpp*)
        and all of ($ftype*)
        and all of ($path*)
}
rule Glupteba: malware dropper
{

    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-09-06"
        Note = "Attempts to detect the Glupteba malware; needs some tuning"

    strings:
        $str1 = "struct { F uintptr; serverRandom []uint8; clientRandom []uint8; version uint16; suite *tls.cipherSuite; masterSecret []uint8 }" ascii fullword
        $str2 = "func(context.Context, io.ReadWriter, http.socksAuthMethod) error" ascii fullword
        $str3 = "*http.socksUsernamePassword }" ascii
        $str4 = "net/http.(*socksDialer).validateTarget" ascii fullword
        $str5 = "net/http.(*socksCommand).String" ascii fullword
        $str6 = "net/http.socksCommand.String" ascii fullword
        $str7 = "type..hash.net/http.socksUsernamePassword" ascii fullword

        $str8 = "github.com/cenkalti/backoff." ascii
        $str9 = "golang.org/x/sys/windows.LookupAccountName" ascii fullword
        $str10 = "golang.org/x/sys/windows.LookupSID" ascii fullword

        $str00 = "json:\"login\"" ascii fullword
        $str01 = "Passwords" ascii fullword
        $str02 = "json:\"passwords\"" ascii fullword
        $str03 = "main.Password" ascii fullword
        $str04 = "main.postData" ascii fullword
        $str05 = "net/http.Post" ascii fullword
        $str06 = "json:\"browser_name\"" ascii fullword
        $str07 = "json:\"date_created\"" ascii fullword
        $str08 = "json:\"domain\"" ascii fullword
        $str09 = "encoding/json" ascii
        $str010 = "hash.main.Password" ascii

    condition:
        (
            uint16(0) == 0x5a4d
            and filesize < 20000KB
            and 8 of them
        )
        or
        (
            all of them
        )
}
rule GodLua_Linux: linuxmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $tmp0 = "/tmp" ascii fullword
      $tmp1 = "TMPDIR" ascii

      $str1 = "\"description\": \"" ascii fullword
      $str2 = "searchers" ascii fullword
      $str3 = "/dev/misc/watchdog" ascii fullword
      $str4 = "/dev/wdt" ascii fullword
      $str5 = "/dev/misc/wdt"
      $str6 = "lcurl.safe" ascii fullword
      $str7 = "luachild" ascii fullword
      $str8 = "cjson.safe" ascii fullword
      $str9 = "HostUrl" ascii fullword
      $str10 = "HostConnect" ascii fullword
      $str11 = "LUABOX" ascii fullword
      $str12 = "Infinity" ascii fullword
      $str13 = "/bin/sh" ascii fullword
      $str14 = /\.onion(\.)?/ ascii fullword
      $str15 = "/etc/resolv.conf" ascii fullword
      $str16 = "hosts:" ascii fullword

      $resolvers = /([0-9]{1,3}\.){3}[0-9]{1,3}:53,([0-9]{1,3}\.){3}[0-9]{1,3},([0-9]{1,3}\.){3}[0-9]{1,3}:5353,([0-9]{1,3}\.){3}[0-9]{1,3}:443/ ascii

      $identifier0 = "$LuaVersion: God " ascii
      $identifier1 = /fbi\/d\.\/d.\/d/ ascii
      $identifier2 = "Copyright (C) FBI Systems, 2012-2019, https://fbi.gov" fullword ascii
      $identifier3 = "God 5.1"

   condition:
      uint16(0) == 0x457f
      and
      (
         all of them
         or
         (
            any of ($identifier*)
            and $resolvers
            and any of ($tmp*)
            and 4 of ($str*)
         )
         or
         (
            any of ($identifier*)
            and any of ($tmp*)
            and 4 of ($str*)
         )
      )
}

rule JSWorm: malware
{
    strings:
        $name00 = "JSWORM" nocase

        $str00 = "DECRYPT.txt" nocase
        $str02 = "cmd.exe"
        $str03 = "/c reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"zapiska\" /d \"C:\\ProgramData\\"
        $str04 = /\/c taskkill.exe taskkill \/f \/im (store|sqlserver|dns|sqlwriter)\.exe/
        $str05 = "/c start C:\\ProgramData\\"
        $str06 = "/c vssadmin.exe delete shadows /all /quiet"
        $str07 = "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures -y"
        $str08 = "/c bcdedit /set {default} recoveryenabled No -y"
        $str09 = "/c wbadmin delete catalog -quiet"
        $str10 = "/c wmic shadowcopy delete -y"

        $uniq00 = "fuckav"
        $uniq01 = "DECRYPT.hta" nocase
        $uniq02 = "Backup e-mail for contact :"
        $uniq03 = "<HTA:APPLICATION APPLICATIONNAME=" nocase

        /* suspicious APIs
            $api00 = "TerminateProcess"
            $api01 = "IsProcessorFeaturePresent"
            $api02 = "IsDebuggerPresent"
        */

    condition:
        uint16(0) == 0x5a4d
        and
        (
            ($name00 and 5 of ($str*))
            or
            (5 of ($str*) and 2 of ($uniq*))
            or
            ($name00 and any of ($uniq*))
        )
}
rule KPOT_v2: winmalware infostealer
{
    meta:
        Description = "Attempts to detect KPOT version 2 payloads"
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-05"
    strings:
        $str01 = "%s: " ascii fullword
        $str02 = " _%s_" ascii fullword
        $str03 = "0|%S|%s|%s|%s" ascii fullword
        $str04 = "%s | %02d/%04d | %s | %s | %s" ascii fullword
        $str05 = "%s | %s | %s | %s | %s | %s | %s | %d | %s" ascii fullword
        $str06 = "%s: %s | %02d/%04d | %s" ascii fullword
        $str07 = "%s = %s" ascii fullword
        $str08 = "password-check" ascii fullword

        $conf_re1 = /(SMTP|POP3|IMAP)\sServer/ wide
        $conf_re2 = /(SMTP|POP3|IMAP)\s(User|Password|Port)/ wide

        $conf01 = "*.config" ascii wide fullword
        $conf02 = "HTTP Server URL" ascii wide fullword

        $conf03 = "%s: %d" ascii wide fullword
        $conf04 = "%s\\Outlook.txt" ascii wide fullword

    condition:
        uint16(0) == 0x5a4d
        and all of ($str*)
        and all of ($conf_re*)
        and all of ($conf0*)
}
rule RedGhost_Linux: postexploitation linuxmalware
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-07"
        Reference = "https://github.com/d4rk007/RedGhost/"

    strings:
        $name = "[ R E D G H O S T - P O S T  E X P L O I T - T O O L]" ascii

        $feature0 = "Payloads" ascii
        $feature1 = "SudoInject" ascii
        $feature2 = "lsInject" ascii
        $feature3 = "Crontab" ascii
        $feature4 = "GetRoot" ascii
        $feature5 = "Clearlogs" ascii
        $feature6 = "MassinfoGrab" ascii
        $feature7 = "CheckVM" ascii
        $feature8 = "MemoryExec" ascii
        $feature9 = "BanIP" ascii

        $func0 = "checkVM(){" ascii
        $func1 = "memoryexec(){" ascii
        $func2 = "banip(){" ascii
        $func3 = "linprivesc(){" ascii
        $func4 = "dirty(){" ascii
        $func5 = "Ocr(){" ascii
        $func6 = "clearlog(){" ascii
        $func7 = "conmethods(){" ascii
        $func8 = "add2sys(){" ascii

        //$header = "#!/bin/bash" ascii

    condition:
      // #!/bin/bash header
      (uint16be(0x0) == 0x2321 and 
      for any i in (0..64) : (
          uint16be(i) == 0x2f62 and uint8(i+2) == 0x68
      ))
      and
      ($name or 5 of them)
}
rule REMCOS_RAT_variants: remcos rat winmalware
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-18"
        Description = "Detects multiple variants of REMCOS seen in the wild. Created by modifying and combining several of Florian's recent REMCOS ruleset. This rule aims for broader detection than the original ruleset, which used separate rules for each variant. If you do decide to break it into individual rules, the YARA strings variable names are grouped by the REMCOS variant type."

    strings:

        $funcs1 = "autogetofflinelogs" ascii fullword
        $funcs2 = "clearlogins" ascii fullword
        $funcs3 = "getofflinelogs" ascii fullword
        $funcs4 = "execcom" ascii fullword
        $funcs5 = "deletekeylog" ascii fullword
        $funcs6 = "remscriptexecd" ascii fullword
        $funcs7 = "getwindows" ascii fullword
        $funcs8 = "fundlldata" ascii fullword
        $funcs9 = "getfunlib" ascii fullword
        $funcs10 = "autofflinelogs" ascii fullword
        $funcs11 = "getclipboard" ascii fullword
        $funcs12 = "getscrslist" ascii fullword
        $funcs13 = "offlinelogs" ascii fullword
        $funcs14 = "getcamsingleframe" ascii fullword
        $funcs15 = "listfiles" ascii fullword
        $funcs16 = "getproclist" ascii fullword
        $funcs17 = "onlinelogs" ascii fullword
        $funcs18 = "getdrives" ascii fullword
        $funcs19 = "remscriptsuccess" ascii fullword
        $funcs20 = "getcamframe" ascii fullword

        $str_a1 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
        $str_a2 = "C:\\WINDOWS\\system32\\userinit.exe" ascii fullword
        $str_a3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a4 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a5 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii fullword

        $str_b1 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide fullword
        $str_b2 = "Executing file: " ascii fullword
        $str_b3 = "GetDirectListeningPort" ascii fullword
        $str_b4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide fullword
        $str_b5 = "licence_code.txt" ascii fullword
        $str_b6 = "\\restart.vbs" wide fullword
        $str_b7 = "\\update.vbs" wide fullword
        $str_b8 = "\\uninstall.vbs" wide fullword
        $str_b9 = "Downloaded file: " ascii fullword
        $str_b10 = "Downloading file: " ascii fullword
        $str_b11 = "KeepAlive Enabled! Timeout: %i seconds" ascii fullword
        $str_b12 = "Failed to upload file: " ascii fullword
        $str_b13 = "StartForward" ascii fullword
        $str_b14 = "StopForward" ascii fullword
        $str_b15 = "fso.DeleteFile \"" wide fullword
        $str_b16 = "On Error Resume Next" wide fullword
        $str_b17 = "fso.DeleteFolder \"" wide fullword
        $str_b18 = "Uploaded file: " ascii fullword
        $str_b19 = "Unable to delete: " ascii fullword
        $str_b20 = "while fso.FileExists(\"" wide fullword

        $str_c0 = "[Firefox StoredLogins not found]" ascii fullword
        $str_c1 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii fullword
        $str_c2 = "[Chrome StoredLogins found, cleared!]" ascii fullword
        $str_c3 = "[Chrome StoredLogins not found]" ascii fullword
        $str_c4 = "[Firefox StoredLogins cleared!]" ascii fullword
        $str_c5 = "Remcos_Mutex_Inj" ascii fullword
        $str_c6 = "\\logins.json" ascii fullword
        $str_c7 = "[Chrome Cookies found, cleared!]" ascii fullword
        $str_c8 = "[Firefox Cookies not found]" ascii fullword
        $str_c9 = "[Chrome Cookies not found]" ascii fullword
        $str_c10 = "[Firefox cookies found, cleared!]" ascii fullword
        $str_c11 = "mscfile\\shell\\open\\command" ascii fullword
        $str_c12 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii fullword
        $str_c13 = "eventvwr.exe" ascii fullword


    condition:
        uint16(0) == 0x5a4d and filesize < 600KB
        and
        (
            ((8 of ($funcs*)) or all of ($funcs*))
            or
            ((1 of ($str_a*) and 4 of them) or all of ($str_a*))
            or
            ((8 of ($str_b*)) or all of ($str_b*))
            or
            all of ($str_c*)
         )
}
rule SilentTrinity_Delivery_Document
{
   meta:

      Description = "Attempts to detect SilentTrinity delivery documents"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-19"
      Reference = "https://countercept.com/blog/hunting-for-silenttrinity/"

   strings:

      $s0 = "VBE7.DLL" fullword ascii
      $s1 = "TargetPivotTable" fullword ascii
      $s2 = "DocumentUserPassword" fullword wide
      $s3 = "DocumentOwnerPassword" fullword wide
      $s4 = "Scripting.FileSystemObject" fullword wide
      $s5 = "MSXML2.ServerXMLHTTP" fullword wide
      $s6 = "Win32_ProcessStartup " fullword ascii
      $s7 = "Step 3: Start looping through all worksheets" fullword ascii
      $s8 = "Step 2: Start looping through all worksheets" fullword ascii
      $s9 = "Stringer" fullword wide
      $s10 = "-decode -f" fullword wide
      $s11 = "2. Da biste pogledali dokument, molimo kliknite \"OMOGU" fullword wide
   
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB 
      and (8 of ($s*) or all of them)
}
rule SilentTrinity
{
   meta:
      Description = "Attempts to detect the SilentTrinity malware family"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-19"
      Reference = "https://countercept.com/blog/hunting-for-silenttrinity/"

    strings:

        $pdb01 = "SILENTTRINITY.pdb" ascii

        $str01  = "Found {0} in zip" ascii fullword
        $str02  = "{0} not in zip file" ascii fullword
        $str03  = "Invalid HMAC: {0}" ascii fullword
        $str04  = "Attempting HTTP GET to {0}" ascii fullword
        $str05  = "Downloaded {0} bytes" ascii fullword
        $str06  = "Error downloading {0}: {1}" ascii fullword
        $str07  = "Attempting HTTP POST to {0}" ascii fullword
        $str08  = "POST" ascii fullword
        $str09  = "application/octet-stream" ascii fullword
        $str10  = "Error sending job results to {0}: {1}" ascii fullword
        $str11  = ".dll" ascii fullword
        $str12  = "Trying to resolve assemblies by staging zip" ascii fullword
        $str13  = "'{0}' loaded" ascii fullword
        $str14  = "Usage: SILENTTRINITY.exe <URL> [<STAGE_URL>]" ascii fullword
        $str15 = "IronPython.dll" ascii fullword
        $str16  = "IronPythonDLL" ascii fullword
        $str17 = "DEBUG" ascii fullword
        $str18  = "Main.py" ascii fullword
        $str19  = "Execute" ascii fullword
        $str20  = "SILENTTRINITY.Properties.Resources" ascii fullword
        $str21  = ".zip" ascii fullword

        $a00  = "HttpGet" ascii fullword
        $a01  = "System.Net" ascii fullword
        $a02  = "Target" ascii fullword
        $a03  = "WebClient" ascii fullword
        $a04 = "get_Current" ascii fullword
        $a05  = "Endpoint" ascii fullword
        $a06  = "AesDecrypt" ascii fullword
        $a07  = "AesEncrypt" ascii fullword
        $a08  = "cert" ascii fullword
        $a09  = "WebRequest" ascii fullword
        $a10  = "HttpPost" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (8 of ($str*) or (all of ($a*) and $pdb01) or $pdb01)
        )
}     
rule TA505_FlowerPippi: TA505 financial backdoor winmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $pipi = "pipipipip" ascii fullword
      $pdb0  = "Loader.pdb" ascii fullword

      $str0  = "bot.php" ascii fullword
      $str1  = "%.2X" ascii fullword
      $str2  = "sd.bat" ascii fullword
      $str3  = "open" ascii fullword
      $str4  = "domain" ascii fullword
      $str5 = "proxy" ascii fullword
      $str6  = ".exe" ascii fullword
      $str7 = "Can't launch EXE file" ascii fullword
      $str8  = "Can't load file" ascii fullword
      $str9  = ".dll" ascii fullword
      $str10  = "Dll function not found" ascii fullword
      $str11  = "Can't load Dll" ascii fullword
      $str12  = "__start_session__" ascii fullword
      $str13  = "__failed__" ascii fullword
      $str14  = "RSDSG" ascii fullword
      $str15  = "ProxyServer" ascii fullword
      $str16  = ":Repeat" ascii fullword
      $str17  = "del \"%s\"" ascii fullword
      $str18  = "if exist \"%s\" goto Repeat" ascii fullword
      $str19  = "rmdir \"%s" ascii fullword
      $str20  = "del \"%s\"" ascii fullword
      $str21  = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii fullword
      $str22  = "ProxyEnable" ascii fullword
      $str23 = ".00cfg" ascii fullword
      $str24 = ".idata" ascii fullword

      $api0  = "IsProcessorFeaturePresent" ascii fullword
      $api1  = "IsDebuggerPresent" ascii fullword
      $api2  = "HttpOpenRequestA" ascii fullword
      $api3  = "InternetCrackUrlA" ascii fullword
      $api4  = "InternetOpenW" ascii fullword
      $api5  = "HttpSendRequestW" ascii fullword
      $api6  = "InternetCloseHandle" ascii fullword
      $api7  = "InternetConnectA" ascii fullword
      $api8  = "InternetSetOptionW" ascii fullword
      $api9  = "InternetReadFile" ascii fullword
      $api10  = "WININET.dll" ascii fullword
      $api11 = "URLDownloadToFileA" ascii fullword

   condition:
      uint16(0) == 0x5a4d and filesize < 700KB
      and
      (
         (10 of ($str*) and $pipi)
         or
         (10 of ($str*) and $pdb0)
         or
         (10 of ($str*) and 5 of ($api*))
         or
         (all of them)
      )
}
rule WatchDog_Botnet: botnet linuxmalware exploitation cve_2019_11581 cve_2019_10149
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-22"
        Reference = "https://twitter.com/polarply/status/1153232987762376704"

    strings:

        // $email = "jeff4r@watchbog.com"
        $py0 = "libpython" ascii
        //$py1 = "jail.py" ascii fullword

        //$rcpt1 = "RCPT TO:<${run{\x2Fbin\x2Fsh\t-c\t\x22bash\x20\x2Ftmp\x2Fbaby\x22}}@localhost>" ascii fullword
        //$rcpt2 = /RCPT TO:<\$\{run\{\\x2Fbin\\x2Fsh\\t-c\\t\\x22curl\\x20https\\x3a\\x2F\\x2Fpastebin.com\\x2Fraw/

        $str0 = "*/3 * * * * root wget -q -O- https://pastebin.com/raw/" ascii
        $str1 = "*/1 * * * * root curl -fsSL https://pastebin.com/raw/" ascii
        $str6 = "onion.to"
        $str7 = /https?:\/\/pastebin.com\/raw/ nocase
        $str8 = "http://icanhazip.com/"
        $str9 = "http://ident.me/"

        $scan0 = "Scan_run"
        $scan1 = "scan_nexus"
        $scan2 = "scan_couchdb"
        $scan3 = "scan_jenkins"
        $scan4 = "scan_laravel"
        $scan5 = "scan_redis"

        $exploit01 = "CVE_2015_4335"
        $exploit02 = "CVE_2018_1000861"
        $exploit03 = "CVE_2018_8007"
        $exploit04 = "CVE_2019_1014"
        $exploit05 = "CVE_2019_11581"
        $exploit06 = "CVE_2019_7238"

        $pwn0 = "pwn_couchdb"
        $pwn1 = "pwn_jenkins"
        $pwn2 = "pwn_jira"
        $pwn3 = "pwn_nexus"
        $pwn4 = "pwn_redis"
        $pwn5 = "pwn_exim"

        $payload = /payload(s)/ nocase
        $jira_token = "atlassian.xsrf.token=%s" ascii fullword
        $jira_cmd = "set ($cmd=\"%s\")" ascii fullword
        $jira_id = "JSESSIONID=%s" ascii fullword

        /*
        dont know if i really want to add these

            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_4"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0b"
            $user_agent00 = "Mozilla_5_0_Macintosh_Intel_Mac"
            $user_agent00 = "Mozilla_5_0_Windows_NT_5_1_Apple"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_2"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_3"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_4"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_5"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_6"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_Win64"
            $user_agent00 = "Mozilla_5_0_Windows_U_MSIE_9_0_W"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_2"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_3"
            $user_agent00 = "Mozilla_5_0_X11_Linux_i686_U_Gec"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_en_US_Ap"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_i686_en"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_x86_64_z"
            $user_agent00 = "Mozilla_5_0_X11_Ubuntu_Linux_x86"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_8_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_2"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_3"
            $user_agent00 = "Mozilla_5_0_iPad_U_CPU_OS_4_2_1"
        */

    condition:
        uint32be(0x0) == 0x7f454c46
        and $py0
        and
        (
            (all of ($pwn*) and all of ($scan*))
            or
            ($payload and all of ($jira*) and 5 of ($str*))
            or
            (all of ($str*) and all of ($exploit*))
        )
}
rule Winnti_Linux: linuxmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str0 = "HIDE_THIS_SHELL=x"
      $str1 = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null" ascii fullword
      $str2 = "mutex.max:  %lu" ascii fullword
      $str3 = "mutex.err:  %lu" ascii fullword
      $str4 = "/tmp/ans.log" ascii fullword
      $str5 = "mutex.used: %lu" ascii fullword
      $str6 = "Warning: Some of the worker threads may have failed to exit." ascii fullword
      $str7 = "line %d - " ascii fullword
      $str8 = "Warning an error has occurred when trying to obtain a worker task." ascii fullword
      $str9 = "6CMutex" ascii fullword
      $str10 = "Failed to obtain an empty task from the free tasks queue." ascii fullword
      $str11 = "A problem was detected in the queue (expected NULL, but found a different value)." ascii fullword
      $str12 = "Failed to a task to the free tasks queue during initialization." ascii fullword
      $str13 = "/var/run/libudev1.pid" ascii fullword
      $str14 = "__pthread_key_create" ascii fullword
      $str15 = "The threadpool received as argument is NULL." ascii fullword
      $str16 = "Failed to enqueue a task to free tasks queue." ascii fullword
      $str17 = "Failed to obtain a task from the jobs queue." ascii fullword
      $str18 = "Failed to add a new task to the tasks queue." ascii fullword
      $str19 = "setsockopt  failed" ascii fullword
      $str20 = "libxselinux.so" ascii fullword
      $str21 = "/lib/libxselinux" ascii fullword

    condition:
      uint16(0) == 0x457f
      and
      8 of them
}
rule SUSP_msg_CVE_2023_23397_Mar23 {
   meta:
      description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
      author = "delivr.to"
      date = "2023-03-15"
      score = 60
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
   condition:
      uint32be(0) == 0xD0CF11E0 and
      uint32be(4) == 0xA1B11AE1 and
      $app and 
      $rfp
}rule SUSP_OneNote_Repeated_FileDataReference_Feb23 {
   meta:
      description = "Repeated references to files embedded in OneNote file. May indicate multiple copies of file hidden under image, as leveraged by Qakbot et al."
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* FileDataReference <ifndf>{GUID} */
      /* https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf */
      $fref = { 3C 00 69 00 66 00 6E 00 64 00 66 00 3E 00 7B 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      #fref > (#fdso * 4)
}rule SUSP_OneNote_RTLO_Character_Feb23 {
   meta:
      description = "Presence of RTLO Unicode Character in a OneNote file with embedded files"
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* RTLO */
      $rtlo = { 00 2E 20 }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      $rtlo
}rule SUSP_OneNote_Win_Script_Encoding_Feb23 {
   meta:
      description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
      author = "delivr.to"
      date = "2023-02-19"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* Windows Script Encoding Header */
      $wse = { 23 40 7E 5E }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      $wse
}rule SUSP_PDF_MHT_ActiveMime_Sept23 {
    meta:
      description = "Presence of MHT ActiveMime within PDF for polyglot file"
      author = "delivr.to"
      date = "2023-09-04"
      score = 70
      reference = "https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html"

    strings:
        $mht0 = "mime" ascii nocase
        $mht1 = "content-location:" ascii nocase
        $mht2 = "content-type:" ascii nocase
        $act  = "edit-time-data" ascii nocase
     
    condition:
        uint32(0) == 0x46445025 and
        all of ($mht*) and
        $act
}rule SUSP_SVG_Onload_Onerror_Jul23 {
   meta:
      description = "Presence of onload or onerror attribute in SVG file"
      author = "delivr.to"
      date = "2023-07-22"
      score = 40
   strings:
      $svg = "svg" ascii wide nocase

      $onload = "onload" ascii wide nocase
      
      $onerror = "onerror" ascii wide nocase

   condition:
      ($svg) and 
      ($onload or $onerror)
}import "elf"

rule blackmatter_linux_decryptor : Ransomware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <https://dissectingmalwa.re>"
      description = "Detects BlackMatter Linux Ransomware Version 1.6.0.2 to 1.6.0.4 with ESXI capabilities (Decryptor)"
      reference = "https://github.com/f0wl/configmatter-linux"
      date = "2021-10-16"
      tlp = "WHITE"
      hash = "e48c87a1bb47f60080320167d73f30ca3e6e9964c04ce294c20a451ec1dff425"
   
   strings:
      // Functions
      $func = "bool app::esxi_utils::get_process_list(std::vector<std::basic_string<char> >&)" ascii
      
      // Configuration
      $cfg1 = "disk.dark-size" fullword ascii
      $cfg2 = "disk.white-size" fullword ascii
      $cfg3 = "disk.min-size" fullword ascii
      
      // Logging
      $log1 = "[FW Stopping]" ascii
      $log2 = "[FILE]" ascii
      $log3 = "Removing Self Executable..." ascii
      $log4 = "Another Instance Currently Running..." ascii

      // File name "/tmp/.DBFD055C-9CF2-4BB8-908E-6DA22321BF17"
      $tmpFileName = {44424644C744241430353543C74424182D394346C744241C322D3442C744242042382D39C74424243038452DC744242836444132C744242C32333231C744243042463137}
      
      // Rolling XOR to decrypt the config blob
      $configDecrypt = {4885ff74424929f84983f82074394901f831c94531c90f1f8400000000000fb61084d274190fb6340f4038f274104883c10131f24883f9208810490f44c94883c0014c39c075d7}

      // SHA-1 constant values
      $sha1Constants = {c70701234567c7470489abcdefc74708fedcba98c7470c76543210c74710f0e1d2c3}
   
   condition:
      uint16(0) == 0x457f 
      and filesize < 5000KB
      and elf.number_of_sections > 30
      and for any i in (12..elf.number_of_sections-12):
            (
                (elf.sections[i].name == ".app.version") and
                (elf.sections[i+1].name == ".cfgDTD")
            )
      and $func
      and 3 of ($cfg*)
      and 3 of ($log*)
      and $tmpFileName
      and $configDecrypt
      and $sha1Constants
}import "elf"

rule blackmatter_linux_encryptor : Ransomware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <https://dissectingmalwa.re>"
      description = "Detects BlackMatter Linux Ransomware Version 1.6.0.2 to 1.6.0.4 with ESXI capabilities (Encryptor)"
      reference = "https://github.com/f0wl/configmatter-linux"
      date = "2021-10-16"
      tlp = "WHITE"
      hash1 = "6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502"
      hash2 = "d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82"
      hash3 = "1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f"
   
   strings:
      // Functions
      $func1 = "bool app::esxi_utils::get_process_list(std::vector<std::basic_string<char> >&)" ascii
      $func2 = "bool app::master_proc::process_file_encryption(std::shared_ptr<app::setup_impl>, size_t&, size_t&, size_t&)" ascii
      $func3 = "bool app::file_encrypter::process_file(const string&)" ascii
      
      // Command&Control
      $cc1 = "host_hostname" fullword ascii
      $cc2 = "host_os" fullword ascii
      $cc3 = "bot_version" fullword ascii
      $cc4 = "bot_company" fullword ascii
      $cc5 = "stat_all_files" fullword ascii
      $cc6 = "stat_not_encrypted" fullword ascii
      
      // Configuration
      $cfg1 = "landing.key" fullword ascii
      $cfg2 = "landing.bot-id" fullword ascii
      $cfg3 = "kill-vm.ignore-list" fullword ascii
      $cfg4 = "kill-process.list" fullword ascii
      $cfg5 = "disk.dark-size" fullword ascii
      $cfg6 = "disk.white-size" fullword ascii
      $cfg7 = "disk.min-size" fullword ascii
      
      // Logging
      $log1 = "[FW Stopping]" ascii
      $log2 = "[WEB]" ascii
      $log3 = "[FILE]" ascii
      $log4 = "Removing Self Executable..." ascii
      $log5 = "Another Instance Currently Running..." ascii

      // File name "/tmp/.DBFD055C-9CF2-4BB8-908E-6DA22321BF17"
      $tmpFileName = {44424644C744241430353543C74424182D394346C744241C322D3442C744242042382D39C74424243038452DC744242836444132C744242C32333231C744243042463137}
      
      // Rolling XOR to decrypt the config blob
      $configDecrypt = {4885ff74424929f84983f82074394901f831c94531c90f1f8400000000000fb61084d274190fb6340f4038f274104883c10131f24883f9208810490f44c94883c0014c39c075d7}

      // SHA-1 constant values
      $sha1Constants = {c70701234567c7470489abcdefc74708fedcba98c7470c76543210c74710f0e1d2c3}

      // cpuid syscall
      $cpuidCall = {81fb47656e7575ceb8010000000fa281e10000004074bf48c74500000000005b5d415cc3}

      // Timestamp calculation
      $gettimeofday = {e86f30ffff488b0424488b4c240848bacff753e3a59bc420488943084889c848c1f93f48f7ea48c1fa074829ca668953104883c4185b5d415c415d415e415fc3}
   
   condition:
      uint16(0) == 0x457f 
      and filesize < 5000KB
      and elf.number_of_sections > 30
      and for any i in (12..elf.number_of_sections-12):
            (
                (elf.sections[i].name == ".app.version") and
                (elf.sections[i+1].name == ".cfgETD")
            )
      and any of ($func*)
      and 3 of ($cc*)
      and 3 of ($cfg*)
      and 3 of ($log*)
      and $tmpFileName
      and $configDecrypt
      and $sha1Constants
      and $cpuidCall
      and $gettimeofday
}import "pe"

rule danabot_main {
   meta:
      description = "Detects the main component of DanaBot"
      author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
      reference = "https://github.com/f0wl/danaConfig"
      date = "2021-11-14"
      tlp = "WHITE"
      hash1 = "77ff83cc49d6c1b71c474a17eeaefad0f0a71df0a938190bf9a9a7e22531c292"
      hash2 = "e7c9951f26973c3915ffadced059e629390c2bb55b247e2a1a95effbd7d29204"
      hash3 = "ad0ccba36cef1de383182f866478abcd8b91f8e060d03e170987431974dc861e"
   
   strings:
      $s1 = "TProxyTarget" ascii
      $s2 = "TPasswords" ascii

      $w1 = "FILEZILLA1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
      $w2 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" wide //CLSID C:\Windows\system32\wincredui.dll
      $w3 = "F:\\b_system\\FS_Morff\\FS_Temp\\" wide
      $w4 = "MiniInit:Except" wide
      $w5 = "Except:StartConnectSystem" wide
      $w6 = "StealerInformation" wide
      $w7 = "www.google.com/Please log in to your Gmail account" wide

   condition:
      uint16(0) == 0x5a4d
      and filesize > 4000KB
      and filesize < 25000KB 
      and pe.imphash() == "908afa7baa08116e817d0ade28b27ef3"
      and 4 of them
}
rule Deathransom : ransomware {
   meta:
    description = "Detects Deathransom Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    reference = "https://dissectingmalwa.re/quick-and-painless-reversing-deathransom-wacatac.html"
    date = "2019-11-20"
    hash1 = "7c2dbad516d18d2c1c21ecc5792bc232f7b34dadc1bc19e967190d79174131d1"
      
   strings:
    $s1 = "https://localbitcoins.com/buy_bitcoins" fullword ascii
    $s2 = "read_me.txt" fullword wide
    $s3 = "$recycle.bin" fullword wide
    $s4 = "bootsect.bak" fullword wide
    $s5 = "files are encrypted." fullword ascii
    $s6 = "select * from Win32_ShadowCopy" fullword wide
    $s7 = "To be sure we have the decryptor and it works you can send an" fullword ascii
    $s8 = "All your files, documents, photos, databases and other important" fullword ascii
    $s9 = "Win32_ShadowCopy.ID='%s'" fullword wide
    $s10 = "email death@firemail.cc  and decrypt one file for free. But this" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      5 of them
} 
rule esxi_commands_ransomware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
      description = "Detects commands issued by Ransomware to interact with ESXi VMs"
      date = "2021-12-20"
      tlp = "WHITE"
      
      // AvosLocker
      hash0 = "e9a7b43acdddc3d2101995a2e2072381449054a7d8d381e6dc6ed64153c9c96a"
      // BlackCat
      hash1 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"
      // BlackMatter 
      hash2 = "d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82"
      // HelloKitty  
      hash3 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
      // Hive
      hash4 = "822d89e7917d41a90f5f65bee75cad31fe13995e43f47ea9ea536862884efc25"
      // REvil
      hash5 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"

   strings:
      $keyword0 = "esxi" ascii nocase
      $keyword1 = "vm" ascii nocase
      $keyword2 = "process" ascii nocase
      $keyword3 = "kill" ascii nocase
      $keyword4 = "list" ascii nocase
      $keyword5 = "stop" ascii nocase
     
      // observed in: BlackMatter
      $keyword6 = "firewall" ascii nocase

      // VMware commandline tools
      $command0 = "esxcli" ascii
      $command1 = "esxcfg" ascii
      $command2 = "vicfg" ascii
      $command3 = "vmware-cmd" ascii
      $command4 = "vim-cmd" ascii

      // observed in: Hive, Python ESXi Ransomware, BlackCat
      $command5 = "vmsvc/getallvms" ascii
      $command6 = "vmsvc/power.off" ascii

      // observed in: BlackCat
      $command7 = "vmsvc/snapshot.removeall" ascii
      
      // observed in: BlackMatter, AvosLocker, REvil
      $argument0 = "--type=force" ascii
      $argument1 = "--world-id=" ascii

      // observed in: AvosLocker, Revil
      $argument2 = "--formatter=csv" ascii
      $argument3 = "--format-param=fields==\"WorldID,DisplayName\"" ascii
      
      // observed in: HelloKitty
      $argument4 = "-t=soft" ascii
      $argument5 = "-t=hard" ascii
      $argument6 = "-t=force" ascii
    
      $path0 = "/vmfs"

      // common VMware related file extensions
      $extension0 = "vmx"
      $extension1 = "vmdk"
      $extension2 = "vmsd"
      $extension3 = "vmsn"
      $extension5 = "vmem"
      $extension6 = "vswp"

   condition:
      uint16(0) == 0x457F 
      and filesize < 10MB
      and any of ($keyword*)
      and any of ($command*)
      and (any of ($argument*) or (any of ($path*)) or (any of ($extension*)))
} rule EzuriLoader_revised : LinuxMalware {

    meta:
        author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
        description = "Detects Ezuri Golang Loader/Crypter"
        reference = "https://cybersecurity.att.com/blogs/labs-research/malware-using-new-ezuri-memory-loader"
        date = "2021-01-09"
        tlp = "WHITE"
        hash1 = "ddbb714157f2ef91c1ec350cdf1d1f545290967f61491404c81b4e6e52f5c41f"
        hash2 = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"

    strings:

        // This is a revised rule originally created by AT&T alien labs
        $a1 = "main.runFromMemory"
        $a2 = "main.aesDec"
        $a3 = "crypto/cipher.NewCFBDecrypter"
        $a4 = "/proc/self/fd/%d"
        $a5 = "/dev/null"
        
        // Additionally match on AES constants/SBox as proposed by @DuchyRE
        // https://en.wikipedia.org/wiki/Rijndael_S-box
        $aes = {A5 63 63 C6 84 7C 7C F8}
        $sbox = {63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76}

    condition:
        uint32(0) == 0x464c457f 
        and filesize < 20MB 
        and all of ($a*)
        and $aes and $sbox
}
rule GermanWiper : ransomware { 
  meta: 
    description = "Detects GermanWiper 'Ransomware'" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
    reference = "https://dissectingmalwa.re/tfw-ransomware-is-only-your-side-hustle.html" 
    date = "2019-07-31" 
    hash1 = "41364427dee49bf544dcff61a6899b3b7e59852435e4107931e294079a42de7c" 

  strings: 
    $a1 = "C:\\Bewerbung-Lena-Kretschmer.exe" fullword ascii 
    $a2 = "Copyright VMware." fullword ascii
    $a3 = "Friction Tweeter Casting Transferability" fullword ascii
    $a4 = "expandingdelegation.top" fullword ascii
    $a5 = "Es gibt noch weitere moeglichkeiten Bitcoin zu erwerben" fullword ascii
      
  condition: 
    uint16(0) == 0x5a4d and filesize < 1000KB and 3 of ($a*)
}
import "pe"

rule CRYPTER_Huan {
   meta:
      description = "Detects samples crypted with Huan PE Loader"
      author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
      reference = "https://github.com/frkngksl/Huan"
      date = "2021-08-21"
      tlp = "WHITE"
      
   strings:
      $s0 = "huan" ascii
      $s1 = "[+] Imported DLL Name: " fullword ascii
      $s2 = "[+] Binary is running" fullword ascii
      $s3 = "[+] All headers are copied" fullword ascii
      $s4 = "[+] Data is decrypted! " fullword ascii
      $s5 = "[+] All sections are copied" fullword ascii
      $s6 = "[!] Import Table not found" fullword ascii
      $s7 = "[+] Cannot load to the preferable address" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d
      and pe.imphash() == "f7fd6adbeced3adfa337ae23987ee13e"
      and 4 of ($s*)
      and for any i in (0..pe.number_of_sections):(pe.sections[i].name == ".huan")
}
rule ICMLuaUtil_UACMe_M41 : uac_bypass
{
    meta:
        description = "A Yara rule for UACMe Method 41 -> ICMLuaUtil Elevated COM interface"
        author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
        date = "2021-01-19"
        TLP = "WHITE"
        reference = "https://github.com/hfiref0x/UACME"

    strings:
        $elevation = "Elevation:Administrator!new:" wide ascii

        // IDs as strings, e.g. UACMe Implementation / Ataware Ransomware
        $clsid_CMSTPLUA = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide ascii
        $iid_ICMLuaUtil = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" wide ascii
        
        // IDs as embedded data structures, e.g. LockBit Ransomware
        $clsid_bytes = {95 D1 16 0A 47 6F 64 49 92 87 9F 4B AB 6D 98 27}
        $iid_bytes = {74 6D DD 6E 07 C0 75 4E B7 6A E5 74 09 95 E2 4C}

    condition:
        uint16(0) == 0x5a4d
        and (($elevation and $clsid_CMSTPLUA and $iid_ICMLuaUtil) or ($clsid_bytes and $iid_bytes))
}
import "pe"

rule RANSOM_MountLocker_V2 { 

 meta: 
  description = "Detects Mount Locker Ransomware, Version 2 x86 unpacked" 
  author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
  reference = "https://dissectingmalwa.re/between-a-rock-and-a-hard-place-exploring-mount-locker-ransomware.html" 
  date = "2020-12-20"
  tlp = "WHITE"
  hash1 = "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2"
  hash2 = "e7c277aae66085f1e0c4789fe51cac50e3ea86d79c8a242ffc066ed0b0548037"

strings: 
  //picks up on the Volume Serial Number Permutation in function mw_mutex
  $mutex_shift = { 8b c1 c1 c8 ?? 50 8b c1 c1 c8 ?? 50 8b c1 c1 c8 ?? 50 51}

  $x1 = "powershell.exe -windowstyle hidden -c $mypid='%u';[System.IO.File]::ReadAllText('%s')|iex" fullword wide
  //$x2 = "explorer.exe RecoveryManual.html" fullword wide
  $x2 = "RecoveryManual.html" wide

  $x3 = "expand 32-byte k" fullword ascii
  $x4 = "<b>/!\\ YOUR NETWORK HAS BEEN HACKED /!\\<br>" fullword ascii

  $s1 = "[SKIP] locker.volume.enum > readonly name=%s" fullword wide
  $s2 = "[WARN] locker.dir.check > get_reparse_point gle=%u name=%s" fullword wide
  $s3 = "[ERROR] locker.file > get_size gle=%u name=%s" fullword wide
  $s4 = "[OK] locker > finished" fullword wide

condition: 
  uint16(0) == 0x5a4d and filesize < 600KB
  and pe.imphash() == "1ea39e61089a4ea253fb896bbcf01be5"
  and $mutex_shift 
  and 2 of ($x*) 
  and 2 of ($s*)
} 
rule Netwalker : ransomware { 
  meta: 
    description = "Detects Netwalker Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
    reference = "https://github.com/f0wl/configwalker" 
    date = "2020-10-26" // updated 2021-11-29
    hash1 = "4f7bdda79e389d6660fca8e2a90a175307a7f615fa7673b10ee820d9300b5c60"
    hash2 = "46dbb7709411b1429233e0d8d33a02cccd54005a2b4015dcfa8a890252177df9"
    hash3 = "5d869c0e077596bf0834f08dce062af1477bf09c8f6aa0a45d6a080478e45512"
    hash4 = "ce399a2d07c0851164bd8cc9e940b84b88c43ef564846ca654df4abf36c278e6"

  strings: 
    $conf1 = "svcwait" fullword ascii
    $conf2 = "extfree" fullword ascii
    $conf3 = "encname" fullword ascii
    $conf4 = "spsz" fullword ascii
    $conf5 = "idsz" fullword ascii
    $conf6 = "onion1" fullword ascii
    $conf7 = "onion2" fullword ascii
    $conf8 = "lfile" fullword ascii
    $conf9 = "lend" fullword ascii
    $conf10 = "white" fullword ascii
    $conf11 = "extfree" fullword ascii
    $conf12 = "encname" fullword ascii
    
    $s1 = "taskkill /F /PID" fullword ascii
    $s2 = "{code_id:" fullword ascii
    $s3 = "{id}-Readme.txt" fullword wide
    $s4 = "netwalker" wide ascii
    $s5 = "expand 32-byte kexpand 16-byte k" fullword ascii
    $s6 = "InterfacE\\{b196b287-bab4-101a-b69c-00aa00341d07}" fullword ascii
      
  condition: 
    uint16(0) == 0x5a4d 
    and filesize > 45KB // Size on Disk/1.5
    and filesize < 130KB // Size of Image*1.5
    and 6 of ($conf*) 
    and 3 of ($s*)
}rule revil_linux : Ransomware {

    meta:
        author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
        description = "Detects the Linux version of REvil Ransomware with ESXI capabilities"
        date = "2021-07-05"
        reference = "https://cybersecurity.att.com/blogs/labs-research/revils-new-linux-version"
        tlp = "WHITE"
        hash1 = "3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d"
        hash2 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
        hash3 = "796800face046765bd79f267c56a6c93ee2800b76d7f38ad96e5acb92599fcd4"
        hash4 = "d6762eff16452434ac1acc127f082906cc1ae5b0ff026d0d4fe725711db47763"

    strings:

        // Shell command to kill all running VMs on the ESXI server: esxcli --formatter=csv --format-param=fields=="WorldID,DisplayName" vm process list | awk -F "\"*,\"*" '{system("esxcli vm process kill --type=force --world-id=" $1)}'
        $vmKill = {657378636C69202D2D666F726D61747465723D637376202D2D666F726D61742D706172616D3D6669656C64733D3D22576F726C6449442C446973706C61794E616D652220766D2070726F63657373206C697374207C2061776B202D4620225C222A2C5C222A2220277B73797374656D2822657378636C6920766D2070726F63657373206B696C6C202D2D747970653D666F726365202D2D776F726C642D69643D22202431297D27}
        
        $a1 = "Usage example: elf.exe --path /vmfs/ --threads 5 " fullword ascii
        $a2 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
        $a3 = "[%s] already encrypted" fullword ascii
        $a4 = "Error decoding user_id %d " fullword ascii
        $a5 = " without --path encrypts current dir" fullword ascii
        $a6 = "File [%s] was encrypted" fullword ascii
        $a7 = "File [%s] was NOT encrypted" fullword ascii
        $a8 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
        $a9 = "Error decoding master_pk %d " fullword ascii
        $a10 = "Error decoding sub_id %d " fullword ascii
        $a11 = "Error decoding note_body %d " fullword ascii

    condition:
        uint32(0) == 0x464c457f 
        and filesize < 500KB 
        and 7 of them
}
rule WannaCry : ransomware {
   meta:
    description = "Detects WannaCry Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    reference = "https://dissectingmalwa.re/third-times-the-charm-analysing-wannacry-samples.html"
    date = "2019-07-28"
    hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      
   strings:
    $name = "WanaCrypt0r" wide
    $langNote = "msg/m_english.wnry" ascii
    
    $s1 = "s.wnry" ascii
    $s2 = "taskdl.exe" ascii
    $s3 = "taskse.exe" ascii
    $s4 = "<!-- Windows 10 -->" ascii
    $s5 = "taskse.exed*" ascii
    $s6 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 4MB 
      and $name
      and $langNote
      and 3 of ($s*)
} 
 
rule zipExec : WindowsMalware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
      description = "Detects zipExec Golang Loader/Crypter"
      reference = "https://github.com/Tylous/ZipExec"
      date = "2021-10-29"
      tlp = "WHITE"

   strings:
      $shellExec = "ShellExecute('cmdkey', '/generic:Microsoft_Windows_Shell_ZipFolder:filename=" ascii
      $domainCheck = "GetSystemInformation(\"IsOS_DomainMember\");" ascii
      $tmp = "GetSpecialFolder(2);" ascii
      $wscript = "new ActiveXObject(\"Wscri\"+\"pt.shell\");" ascii
      $regExt = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\HideFileExt" ascii
      $base64Index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" ascii

      // base64 encoded zip file
      $zipEnc = {55 45 73 44 42 42 51 41 43 51 41 49 41 41}

   condition:
      uint16(0) == 0x090a 
      and filesize < 10MB // accounting for chunky Golang Malware
      and $zipEnc
      and 5 of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_MacOS_GORAT_1
{
    meta:
        description = "This rule is looking for specific strings associated with network activity found within the MacOS generated variant of GORAT"
        md5 = "68acf11f5e456744262ff31beae58526"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "SID1=%s" ascii wide
        $s2 = "http/http.dylib" ascii wide
        $s3 = "Mozilla/" ascii wide
        $s4 = "User-Agent" ascii wide
        $s5 = "Cookie" ascii wide
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule APT_Backdoor_PS1_BASICPIPESHELL_1
{
    meta:
        author = "FireEye"
    strings:
        $s1 = "function Invoke-Client()" ascii nocase wide
        $s2 = "function Invoke-Server" ascii nocase wide
        $s3 = "Read-Host 'Enter Command:'" ascii nocase wide
        $s4 = "new-object System.IO.Pipes.NamedPipeClientStream(" ascii nocase wide
        $s5 = "new-object System.IO.Pipes.NamedPipeServerStream(" ascii nocase wide
        $s6 = " = iex $" ascii nocase wide
    condition:
        all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_DShell_1
{
    meta:
        description = "This rule is looking for sections of an integer array which contains the encoded payload along with a selection of Windows functions that are present within a DShell payload"
        md5 = "152fc2320790aa16ef9b6126f47c3cca"
        rev = 4
        author = "FireEye"
    strings:
        $e0 = ",0,"
        $e1 = ",1,"
        $e2 = ",2,"
        $e3 = ",3,"
        $e4 = ",4,"
        $e5 = ",5,"
        $e6 = ",6,"
        $e7 = ",7,"
        $e8 = ",8,"
        $e9 = ",9,"
        $e10 = ",10,"
        $e11 = ",11,"
        $e12 = ",12,"
        $e13 = ",13,"
        $e14 = ",14,"
        $e15 = ",15,"
        $e16 = ",16,"
        $e17 = ",17,"
        $e18 = ",18,"
        $e19 = ",19,"
        $e20 = ",20,"
        $e21 = ",21,"
        $e22 = ",22,"
        $e23 = ",23,"
        $e24 = ",24,"
        $e25 = ",25,"
        $e26 = ",26,"
        $e27 = ",27,"
        $e28 = ",28,"
        $e29 = ",29,"
        $e30 = ",30,"
        $e31 = ",31,"
        $e32 = ",32,"
        $e33 = ",33,"
        $e34 = ",34,"
        $e35 = ",35,"
        $e36 = ",36,"
        $e37 = ",37,"
        $e38 = ",38,"
        $e39 = ",39,"
        $e40 = ",40,"
        $e41 = ",41,"
        $e42 = ",42,"
        $e43 = ",43,"
        $e44 = ",44,"
        $e45 = ",45,"
        $e46 = ",46,"
        $e47 = ",47,"
        $e48 = ",48,"
        $e49 = ",49,"
        $e50 = ",50,"
        $e51 = ",51,"
        $e52 = ",52,"
        $e53 = ",53,"
        $e54 = ",54,"
        $e55 = ",55,"
        $e56 = ",56,"
        $e57 = ",57,"
        $e58 = ",58,"
        $e59 = ",59,"
        $e60 = ",60,"
        $e61 = ",61,"
        $e62 = ",62,"
        $e63 = ",63,"
        $e64 = ",64,"
        $s1 = "GetACP"
        $s2 = "GetOEMCP"
        $s3 = "GetCPInfo"
        $s4 = "WriteConsoleA"
        $s5 = "FindFirstFileA"
        $s6 = "FileTimeToDosDateTime"
        $s7 = "FindNextFileA"
        $s8 = "GetStringTypeA"
        $s9 = "GetFileType"
        $s10 = "CreateFileA"
        $s11 = "GlobalAlloc"
        $s12 = "GlobalFree"
        $s13 = "GetTickCount"
        $s14 = "GetProcessHeap"
        $s15 = "UnhandledExceptionFilter"
        $s16 = "ExitProcess"
        $s17 = "GetModuleFileNameA"
        $s18 = "LCMapStringA"
        $s19 = "GetLocalTime"
        $s20 = "CreateThread"
        $s21 = "ExitThread"
        $s22 = "SetConsoleCtrlHandler"
        $s23 = "FreeEnvironmentStringsA"
        $s24 = "GetVersion"
        $s25 = "GetEnvironmentStrings"
        $s26 = "SetHandleCount"
        $s27 = "SetFilePointer"
        $s28 = "DeleteFileA"
        $s29 = "HeapAlloc"
        $s30 = "HeapReAlloc"
        $s31 = "HeapFree"
        $s32 = "GetCommandLineA"
        $s33 = "GetThreadContext"
        $s34 = "SuspendThread"
        $s35 = "FindFirstFileW"
        $s36 = "FindNextFileW"
        $s37 = "FindClose"
        $s38 = "CreateSemaphoreA"
        $s39 = "ReleaseSemaphore"
        $s40 = "ExpandEnvironmentStringsW"
        $s41 = "lstrlenW"
        $s42 = "GetModuleHandleA"
        $s43 = "GetEnvironmentVariableA"
        $s44 = "RtlCaptureContext"
        $s45 = "GlobalMemoryStatus"
        $s46 = "VirtualAlloc"
        $s47 = "Sleep"
        $s48 = "SystemTimeToTzSpecificLocalTime"
        $s49 = "TzSpecificLocalTimeToSystemTime"
        $s50 = "GetTimeZoneInformation"
        $s51 = "TryEnterCriticalSection"
        $s52 = "LoadLibraryA"
        $s53 = "VirtualFree"
        $s54 = "GetExitCodeThread"
        $s55 = "WaitForSingleObject"
        $s56 = "ResumeThread"
        $s57 = "DuplicateHandle"
        $s58 = "GetCurrentProcess"
        $s59 = "GetCurrentThread"
        $s60 = "GetCurrentThreadId"
        $s61 = "InitializeCriticalSection"
        $s62 = "DeleteCriticalSection"
        $s63 = "SwitchToThread"
        $s64 = "LeaveCriticalSection"
        $s65 = "EnterCriticalSection"
        $s66 = "FormatMessageW"
        $s67 = "SetLastError"
        $s68 = "GetEnvironmentVariableW"
        $s69 = "FreeEnvironmentStringsW"
        $s70 = "GetEnvironmentStringsW"
        $s71 = "SetEnvironmentVariableW"
        $s72 = "GetSystemInfo"
        $s73 = "QueryPerformanceFrequency"
        $s74 = "QueryPerformanceCounter"
        $s75 = "CreateProcessW"
        $s76 = "GetStdHandle"
        $s77 = "GetHandleInformation"
        $s78 = "SetHandleInformation"
        $s79 = "WriteFile"
        $s80 = "GetConsoleOutputCP"
        $s81 = "FreeLibrary"
        $s82 = "GetConsoleScreenBufferInfo"
        $s83 = "MultiByteToWideChar"
        $s84 = "RaiseException"
        $s85 = "RtlUnwind"
        $s86 = "GetCurrentDirectoryW"
        $s87 = "IsDebuggerPresent"
        $s88 = "LocalFree"
        $s89 = "WideCharToMultiByte"
        $s90 = "GetCommandLineW"
        $s91 = "ReadFile"
        $s92 = "GetFileSize"
        $s93 = "CloseHandle"
        $s94 = "CreateFileW"
        $s95 = "LoadLibraryW"
        $s96 = "GetProcAddress"
        $s97 = "GetFileAttributesW"
        $s98 = "GetLastError"
        $s99 = "CommandLineToArgvW"
        $s100 = "MessageBoxA"
        $s101 = "RegEnumValueW"
        $s102 = "RegEnumKeyExW"
        $s103 = "RegDeleteValueW"
        $s104 = "RegFlushKey"
        $s105 = "RegQueryInfoKeyW"
        $s106 = "RegDeleteKeyW"
        $s107 = "RegQueryValueExW"
        $s108 = "RegSetValueExW"
        $s109 = "RegOpenKeyW"
        $s110 = "RegOpenKeyExW"
        $s111 = "RegCreateKeyExW"
        $s112 = "RegCloseKey"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and 105 of ($s*) and $s112 in (3000..4000) and 40 of ($e*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_DShell_2
{
    meta:
        description = "This rule looks for strings specific to the D programming language in combination with a selection of Windows functions that are present within a DShell payload"
        md5 = "e0683f8ee787313cfd2c61cd0995a830"
        rev = 4
        author = "FireEye"
    strings:
        $dlang1 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang2 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang3 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang4 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang5 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang6 = "\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang7 = "\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang8 = "\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang9 = "\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang10 = "\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang11 = "Unexpected '\\n' when converting from type const(char)[] to type int" ascii wide
        $ign1 = "--strip-comments"
        $ign2 = "Usage: rdmd [RDMD AND DMD OPTIONS]"
        $s1 = "CloseHandle"
        $s2 = "CommandLineToArgvW"
        $s3 = "CreateFileA"
        $s4 = "CreateSemaphoreA"
        $s5 = "CreateThread"
        $s6 = "DeleteCriticalSection"
        $s7 = "DeleteFileA"
        $s8 = "DuplicateHandle"
        $s9 = "EnterCriticalSection"
        $s10 = "ExitProcess"
        $s11 = "ExitThread"
        $s12 = "ExpandEnvironmentStringsW"
        $s13 = "FileTimeToDosDateTime"
        $s14 = "FindClose"
        $s15 = "FindFirstFileA"
        $s16 = "FindFirstFileW"
        $s17 = "FindNextFileA"
        $s18 = "FindNextFileW"
        $s19 = "FormatMessageW"
        $s20 = "FreeEnvironmentStringsA"
        $s21 = "FreeEnvironmentStringsW"
        $s22 = "FreeLibrary"
        $s23 = "GetACP"
        $s24 = "GetCPInfo"
        $s25 = "GetCommandLineA"
        $s26 = "GetCommandLineW"
        $s27 = "GetConsoleOutputCP"
        $s28 = "GetConsoleScreenBufferInfo"
        $s29 = "GetCurrentProcess"
        $s30 = "GetCurrentThread"
        $s31 = "GetCurrentThreadId"
        $s32 = "GetEnvironmentStrings"
        $s33 = "GetEnvironmentStringsW"
        $s34 = "GetEnvironmentVariableA"
        $s35 = "GetEnvironmentVariableW"
        $s36 = "GetExitCodeThread"
        $s37 = "GetFileAttributesW"
        $s38 = "GetFileType"
        $s39 = "GetLastError"
        $s40 = "GetModuleFileNameA"
        $s41 = "GetModuleHandleA"
        $s42 = "GetOEMCP"
        $s43 = "GetProcAddress"
        $s44 = "GetProcessHeap"
        $s45 = "GetStdHandle"
        $s46 = "GetStringTypeA"
        $s47 = "GetSystemInfo"
        $s48 = "GetThreadContext"
        $s49 = "GetTickCount"
        $s50 = "GetTimeZoneInformation"
        $s51 = "GetVersion"
        $s52 = "GlobalAlloc"
        $s53 = "GlobalFree"
        $s54 = "GlobalMemoryStatus"
        $s55 = "HeapAlloc"
        $s56 = "HeapFree"
        $s57 = "HeapReAlloc"
        $s58 = "InitializeCriticalSection"
        $s59 = "IsDebuggerPresent"
        $s60 = "LCMapStringA"
        $s61 = "LeaveCriticalSection"
        $s62 = "LoadLibraryA"
        $s63 = "LoadLibraryW"
        $s64 = "LocalFree"
        $s65 = "MessageBoxA"
        $s66 = "MultiByteToWideChar"
        $s67 = "QueryPerformanceCounter"
        $s68 = "QueryPerformanceFrequency"
        $s69 = "RaiseException"
        $s70 = "ReadFile"
        $s71 = "RegCloseKey"
        $s72 = "RegCreateKeyExW"
        $s73 = "RegDeleteKeyW"
        $s74 = "RegDeleteValueW"
        $s75 = "RegEnumKeyExW"
        $s76 = "RegEnumValueW"
        $s77 = "RegFlushKey"
        $s78 = "RegOpenKeyExW"
        $s79 = "RegOpenKeyW"
        $s80 = "RegQueryInfoKeyW"
        $s81 = "RegQueryValueExW"
        $s82 = "RegSetValueExW"
        $s83 = "ReleaseSemaphore"
        $s84 = "ResumeThread"
        $s85 = "RtlCaptureContext"
        $s86 = "RtlUnwind"
        $s87 = "SetConsoleCtrlHandler"
        $s88 = "SetEnvironmentVariableW"
        $s89 = "SetFilePointer"
        $s90 = "SetHandleCount"
        $s91 = "SetLastError"
        $s92 = "Sleep"
        $s93 = "SuspendThread"
        $s94 = "SwitchToThread"
        $s95 = "SystemTimeToTzSpecificLocalTime"
        $s96 = "TryEnterCriticalSection"
        $s97 = "TzSpecificLocalTimeToSystemTime"
        $s98 = "UnhandledExceptionFilter"
        $s99 = "VirtualAlloc"
        $s100 = "VirtualFree"
        $s101 = "WaitForSingleObject"
        $s102 = "WideCharToMultiByte"
        $s103 = "WriteConsoleA"
        $s104 = "WriteFile"
        $s105 = "lstrlenW"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and filesize > 700KB and all of ($s*) and 1 of ($dlang*) and not $ign1 and not $ign2
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_DShell_3
{
    meta:
        description = "This rule looks for strings specific to the D programming language in combination with sections of an integer array which contains the encoded payload found within DShell"
        md5 = "cf752e9cd2eccbda5b8e4c29ab5554b6"
        rev = 3
        author = "FireEye"
    strings:
        $dlang1 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang2 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang3 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang4 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang5 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang6 = "\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang7 = "\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang8 = "\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang9 = "\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang10 = "\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang11 = "Unexpected '\\n' when converting from type const(char)[] to type int" ascii wide
        $e0 = ",0,"
        $e1 = ",1,"
        $e2 = ",2,"
        $e3 = ",3,"
        $e4 = ",4,"
        $e5 = ",5,"
        $e6 = ",6,"
        $e7 = ",7,"
        $e8 = ",8,"
        $e9 = ",9,"
        $e10 = ",10,"
        $e11 = ",11,"
        $e12 = ",12,"
        $e13 = ",13,"
        $e14 = ",14,"
        $e15 = ",15,"
        $e16 = ",16,"
        $e17 = ",17,"
        $e18 = ",18,"
        $e19 = ",19,"
        $e20 = ",20,"
        $e21 = ",21,"
        $e22 = ",22,"
        $e23 = ",23,"
        $e24 = ",24,"
        $e25 = ",25,"
        $e26 = ",26,"
        $e27 = ",27,"
        $e28 = ",28,"
        $e29 = ",29,"
        $e30 = ",30,"
        $e31 = ",31,"
        $e32 = ",32,"
        $e33 = ",33,"
        $e34 = ",34,"
        $e35 = ",35,"
        $e36 = ",36,"
        $e37 = ",37,"
        $e38 = ",38,"
        $e39 = ",39,"
        $e40 = ",40,"
        $e41 = ",41,"
        $e42 = ",42,"
        $e43 = ",43,"
        $e44 = ",44,"
        $e45 = ",45,"
        $e46 = ",46,"
        $e47 = ",47,"
        $e48 = ",48,"
        $e49 = ",49,"
        $e50 = ",50,"
        $e51 = ",51,"
        $e52 = ",52,"
        $e53 = ",53,"
        $e54 = ",54,"
        $e55 = ",55,"
        $e56 = ",56,"
        $e57 = ",57,"
        $e58 = ",58,"
        $e59 = ",59,"
        $e60 = ",60,"
        $e61 = ",61,"
        $e62 = ",62,"
        $e63 = ",63,"
        $e64 = ",64,"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and filesize < 1500KB and 40 of ($e*) and 1 of ($dlang*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GORAT_1
{
    meta:
        description = "This detects if a sample is less than 50KB and has a number of strings found in the Gorat shellcode (stage0 loader). The loader contains an embedded DLL (stage0.dll) that contains a number of unique strings. The 'Cookie' string found in this loader is important as this cookie is needed by the C2 server to download the Gorat implant (stage1 payload)."
        md5 = "66cdaa156e4d372cfa3dea0137850d20"
        rev = 4
        author = "FireEye"
    strings:
        $s1 = "httpComms.dll" ascii wide
        $s2 = "Cookie: SID1=%s" ascii wide
        $s3 = "Global\\" ascii wide
        $s4 = "stage0.dll" ascii wide
        $s5 = "runCommand" ascii wide
        $s6 = "getData" ascii wide
        $s7 = "initialize" ascii wide
        $s8 = "Windows NT %d.%d;" ascii wide
        $s9 = "!This program cannot be run in DOS mode." ascii wide
    condition:
        filesize < 50KB and all of them
}
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GORAT_2
{
    meta:
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and has the Go build ID strings. Then checks for various strings known to be in the Gorat implant including strings used in C2 json, names of methods, and the unique string 'murica' used in C2 comms. A check is done to ensure the string 'rat' appears in the binary over 1000 times as it is the name of the project used by the implant and is present well over 2000 times."
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        rev = 7
        author = "FireEye"
    strings:
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GORAT_3
{
    meta:
        description = "This rule uses the same logic as FE_APT_Trojan_Win_GORAT_1_FEBeta with the addition of one check, to look for strings that are known to be in the Gorat implant when a certain cleaning script is not run against it."
        md5 = "995120b35db9d2f36d7d0ae0bfc9c10d"
        rev = 5
        author = "FireEye"
    strings:
        $dirty1 = "fireeye" ascii nocase wide
        $dirty2 = "kulinacs" ascii nocase wide
        $dirty3 = "RedFlare" ascii nocase wide
        $dirty4 = "gorat" ascii nocase wide
        $dirty5 = "flare" ascii nocase wide
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000 and any of ($dirty*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule APT_Backdoor_Win_GORAT_4
{
    meta:
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and exports numerous functions that are known to be exported by the Gorat implant. This is done in an effort to provide detection for packed samples that may not have other strings but will need to replicate exports to maintain functionality."
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        rev = 8
        author = "FireEye"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and pe.exports("MemoryCallEntryPoint") and pe.exports("MemoryDefaultAlloc") and pe.exports("MemoryDefaultFree") and pe.exports("MemoryDefaultFreeLibrary") and pe.exports("MemoryDefaultGetProcAddress") and pe.exports("MemoryDefaultLoadLibrary") and pe.exports("MemoryFindResource") and pe.exports("MemoryFindResourceEx") and pe.exports("MemoryFreeLibrary") and pe.exports("MemoryGetProcAddress") and pe.exports("MemoryLoadLibrary") and pe.exports("MemoryLoadLibraryEx") and pe.exports("MemoryLoadResource") and pe.exports("MemoryLoadString") and pe.exports("MemoryLoadStringEx") and pe.exports("MemorySizeofResource") and pe.exports("callback") and pe.exports("crosscall2") and pe.exports("crosscall_386")
}
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GORAT_5
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "comms.BeaconData" fullword
        $2 = "comms.CommandResponse" fullword
        $3 = "rat.BaseChannel" fullword
        $4 = "rat.Config" fullword
        $5 = "rat.Core" fullword
        $6 = "platforms.AgentPlatform" fullword
        $7 = "GetHostID" fullword
        $8 = "/rat/cmd/gorat_shared/dllmain.go" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GoRat_Memory
{
    meta:
        description = "Identifies GoRat malware in memory based on strings."
        md5 = "3b926b5762e13ceec7ac3a61e85c93bb"
        rev = 1
        author = "FireEye"
    strings:
        $murica = "murica" fullword
        $rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
        $rat2 = "rat.(*Core).generateBeacon" fullword
        $rat3 = "rat.gJitter" fullword
        $rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
        $rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
        $rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
        $rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
        $rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
        $rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
        $rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
        $rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
        $winblows = "rat/platforms/win.(*winblows).GetStage" fullword
    condition:
        $winblows or #murica > 10 or 3 of ($rat*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Builder_PY_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "25a97f6dba87ef9906a62c1a305ee1dd"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = ".pop(0)])"
        $s2 = "[1].replace('unsigned char buf[] = \"'"
        $s3 = "binascii.hexlify(f.read()).decode("
        $s4 = "os.system(\"cargo build {0} --bin {1}\".format("
        $s5 = "shutil.which('rustc')"
        $s6 = "~/.cargo/bin"
        $s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/
    condition:
        all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Builder_PY_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "d0a830403e56ebaa4bfbe87dbfdee44f"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "LOAD_OFFSET_32 = 0x612"
        $2 = "LOAD_OFFSET_64 = 0x611"
        $3 = "class RC4:"
        $4 = "struct.pack('<Q' if is64b else '<L'"
        $5 = "stagerConfig['comms']['config']"
        $6 = "_x86.dll"
        $7 = "_x64.dll"
    condition:
        all of them and @1[1] < @2[1] and @2[1] < @3[1] and @3[1] < @4[1] and @4[1] < @5[1]
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Builder_PY_REDFLARE_2
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "4410e95de247d7f1ab649aa640ee86fb"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "<510sxxII"
        $2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
        $3 = "parsePluginOutput"
    condition:
        all of them and #2 == 2
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Builder_Win64_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_pe_to_shellcode.rs"
        md5 = "8d949c34def898f0f32544e43117c057"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
        $ss1 = "\x00Stub Size: "
        $ss2 = "\x00Executable Size: "
        $ss3 = "\x00[+] Writing out to file"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Controller_Linux_REDFLARE_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "/RedFlare/gorat_server"
        $2 = "RedFlare/sandals"
        $3 = "goratsvr.CommandResponse" fullword
        $4 = "goratsvr.CommandRequest" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Downloader_Win32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "05b99d438dac63a5a993cea37c036673"
        rev = 1
        author = "FireEye"
    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [1-10] 6A 00 8B [1-8] 5? 6A 00 6A 00 6A 00 8B [1-8] 5? 68 [4] 8B [1-8] 5? FF 15 [4-40] 6A 14 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Downloader_Win64_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1"
        rev = 2
        author = "FireEye"
    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Dropper_Win64_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_dropper.rs"
        md5 = "edcd58ba5b1b87705e95089002312281"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 8D 8D [4] E8 [4] 49 89 D0 C6 [2-6] 01 C6 [2-6] 01 [0-8] C7 44 24 ?? 0E 00 00 00 4C 8D 0D [4] 48 8D 8D [4] 48 89 C2 E8 [4] C6 [2-6] 01 C6 [2-6] 01 48 89 E9 48 8D 95 [4] E8 [4] 83 [2] 01 0F 8? [4] 48 01 F3 48 29 F7 48 [2] 08 48 89 85 [4] C6 [2-6] 01 C6 [2-6] 01 C6 [2-6] 01 48 8D 8D [4] 48 89 DA 49 89 F8 E8 }
        $sb2 = { 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 68 00 00 00 48 8B [2] 48 8D [2] 48 89 [3] 48 89 [3] 0F 11 44 24 ?? C7 44 24 ?? 08 00 00 0C C7 44 24 ?? 00 00 00 00 31 ?? 48 89 ?? 31 ?? 45 31 ?? 45 31 ?? E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Dropper_Win_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_dropper.rs"
        md5 = "edcd58ba5b1b87705e95089002312281"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "\x00matryoshka.exe\x00"
        $s2 = "\x00Unable to write data\x00"
        $s3 = "\x00Error while spawning process. NTStatus: \x0a\x00"
        $s4 = "\x00.execmdstart/Cfailed to execute process\x00"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_ADPassHunt_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { 73 [2] 00 0A 0A 02 6F [2] 00 0A 0B 38 [4] 12 ?? 28 [2] 00 0A 0? 73 [2] 00 0A 0? 0? 0? 6F [2] 00 0A 1? 13 ?? 72 [4] 13 ?? 0? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 1? 3B [4] 11 ?? 72 [4] 28 [2] 00 0A 13 ?? 0? 72 [4] 6F [2] 00 0A 6F [2] 00 0A 13 ?? 38 [4] 11 ?? 6F [2] 00 0A 74 [2] 00 01 13 ?? 11 ?? 72 [4] 6F [2] 00 0A 2C ?? 11 ?? 72 [4] 11 ?? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 6F [2] 00 0A 72 [4] 28 [2] 00 0A }
        $sb2 = { 02 1? 8D [2] 00 01 [0-32] 1? 1F 2E 9D 6F [2] 00 0A 72 [4] 0A 0B 1? 0? 2B 2E 0? 0? 9A 0? 0? 72 [4] 6F [2] 00 0A 2D ?? 06 72 [4] 28 [2] 00 0A 0A 06 72 [4] 0? 28 [2] 00 0A 0A 0? 1? 58 0? 0? 0? 8E 69 32 CC 06 2A }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_ADPassHunt_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "LDAP://" wide
        $s2 = "[GPP] Searching for passwords now..." wide
        $s3 = "Searching Group Policy Preferences (Get-GPPPasswords + Get-GPPAutologons)!" wide
        $s4 = "possibilities so far)..." wide
        $s5 = "\\groups.xml" wide
        $s6 = "Found interesting file:" wide
        $s7 = "\x00GetDirectories\x00"
        $s8 = "\x00DirectoryInfo\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_DNSOVERHTTPS_C2_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'DoHC2' External C2 project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
        $typelibguid1 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_DTRIM_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'dtrim' project, which is a modified version of SharpSploit."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "7760248f-9247-4206-be42-a6952aa46da2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_FLUFFY_1
{
    meta:
        date_created = "2020-12-04"
        date_modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
        $sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
        $ss1 = "\x00Fluffy\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_FLUFFY_2
{
    meta:
        date_created = "2020-12-04"
        date_modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "\x00Asktgt\x00"
        $s2 = "\x00Kerberoast\x00"
        $s3 = "\x00HarvestCommand\x00"
        $s4 = "\x00EnumerateTickets\x00"
        $s5 = "[*] Action: " wide
        $s6 = "\x00Fluffy.Commands\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_GPOHUNT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'gpohunt' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "751a9270-2de0-4c81-9e29-872cd6378303" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_JUSTASK_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "aa59be52-7845-4fed-9ea5-1ea49085d67a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_LUALOADER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'lualoader' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "8b546b49-2b2c-4577-a323-76dc713fe2ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
        md5 = "db0eaad52465d5a2b86fdd6a6aa869a5"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_NOAMCI_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid0 = "7bcccf21-7ecd-4fd4-8f77-06d461fd4d51" ascii nocase wide
        $typelibguid1 = "ef86214e-54de-41c3-b27f-efc61d0accc3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_PRAT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'prat' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "7d1219fb-a954-49a7-96c9-df9e6429a8c7" ascii nocase wide
        $typelibguid1 = "bc1157c2-aa6d-46f8-8d73-068fc08a6706" ascii nocase wide
        $typelibguid2 = "c602fae2-b831-41e2-b5f8-d4df6e3255df" ascii nocase wide
        $typelibguid3 = "dfaa0b7d-6184-4a9a-9eeb-c08622d15801" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_REDTEAMMATERIALS_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "86c95a99-a2d6-4ebe-ad5f-9885b06eab12" ascii nocase wide
        $typelibguid1 = "e06f1411-c7f8-4538-bbb9-46c928732245" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_REVOLVER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
        $typelibguid1 = "b214d962-7595-440b-abef-f83ecdb999d2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPDACL_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "b3c17fb5-5d5a-4b14-af3c-87a9aa941457" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPDNS_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdns' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "d888cec8-7562-40e9-9c76-2bb9e43bb634" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPGOPHER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "83413a89-7f5f-4c3f-805d-f4692bc60173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPNATIVEZIPPER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "de5536db-9a35-4e06-bc75-128713ea6d27" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPNFS_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnfs' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "9f67ebe3-fc9b-40f2-8a18-5940cfed44cf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPPATCHCHECK_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharppatchcheck' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "528b8df5-6e5e-4f3b-b617-ac35ed2f8975" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPSACK_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsack' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "1946808a-1a01-40c5-947b-8b4c3377f742" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPSQLCLIENT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsqlclient' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "13ed03cd-7430-410d-a069-cf377165fbfd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPSTOMP_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = "mscoree.dll" fullword nocase
        $s1 = "timestompfile" fullword nocase
        $s2 = "sharpstomp" fullword nocase
        $s3 = "GetLastWriteTime" fullword
        $s4 = "SetLastWriteTime" fullword
        $s5 = "GetCreationTime" fullword
        $s6 = "SetCreationTime" fullword
        $s7 = "GetLastAccessTime" fullword
        $s8 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPSTOMP_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 3
        author = "FireEye"
    strings:
        $f0 = "mscoree.dll" fullword nocase
        $s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
        $s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
        $s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
        $s3 = "SetCreationTime" fullword
        $s4 = "GetLastAccessTime" fullword
        $s5 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPTEMPLATE_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharptemplate' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "e9e452d4-9e58-44ff-ba2d-01b158dda9bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPWEBCRAWLER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpwebcrawler' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "cf27abf4-ef35-46cd-8d0c-756630c686f1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPZIPLIBZIPPER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpziplibzipper' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "485ba350-59c4-4932-a4c1-c96ffec511ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_TITOSPECIAL_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 5
        author = "FireEye"
    strings:
        $ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
        $ind_s1 = "NtReadVirtualMemory" fullword wide
        $ind_s2 = "WriteProcessMemory" fullword
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($ind*) and any of ($shellcode* )
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_WMISPY_2
{
    meta:
        description = "wql searches"
        md5 = "3651f252d53d2f46040652788499d65a"
        rev = 4
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $str1 = "root\\cimv2" wide
        $str2 = "root\\standardcimv2" wide
        $str3 = "from MSFT_NetNeighbor" wide
        $str4 = "from Win32_NetworkLoginProfile" wide
        $str5 = "from Win32_IP4RouteTable" wide
        $str6 = "from Win32_DCOMApplication" wide
        $str7 = "from Win32_SystemDriver" wide
        $str8 = "from Win32_Share" wide
        $str9 = "from Win32_Process" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of ($str*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_Win64_EXCAVATOR_1
{
    meta:
        date_created = "2020-11-30"
        date_modified = "2020-11-30"
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
        $lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_Win64_EXCAVATOR_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "4fd62068e591cbd6f413e1c2b8f75442"
        rev = 1
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { C7 [2-5] FD 03 00 AC 4C 8D 4D ?? 41 B8 1F 00 10 00 8B [2-5] 48 8B 4D ?? E8 [4] 89 [2-5] 83 [2-5] 00 74 ?? 48 8B 4D ?? FF 15 [4] 33 C0 E9 [4] 41 B8 10 00 00 00 33 D2 48 8D 8D [4] E8 [4] 48 8D 05 [4] 48 89 85 [4] 48 C7 85 [8] 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 C7 44 24 20 01 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4] 48 89 85 [4] 48 83 BD [4] FF 75 ?? 48 8B 4D ?? FF 15 [4] 33 C0 EB [0-17] 48 8D [5] 48 89 ?? 24 30 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 41 B9 02 00 00 00 4C 8B 85 [4] 8B [1-5] 48 8B 4D ?? E8 }
        $enable_dbg_pri = { 4C 8D 45 ?? 48 8D 15 [4] 33 C9 FF 15 [4] 85 C0 0F 84 [4] C7 45 ?? 01 00 00 00 B8 0C 00 00 00 48 6B C0 00 48 8B 4D ?? 48 89 4C 05 ?? B8 0C 00 00 00 48 6B C0 00 C7 44 05 ?? 02 00 00 00 FF 15 [4] 4C 8D 45 ?? BA 20 00 00 00 48 8B C8 FF 15 [4] 85 C0 74 ?? 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 45 ?? 33 D2 48 8B 4D ?? FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Keylogger_Win32_REDFLARE_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "d7cfb9fbcf19ce881180f757aeec77dd"
        rev = 2
        author = "FireEye"
    strings:
        $create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
        $keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Keylogger_Win64_REDFLARE_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "fbefb4074f1672a3c29c1a47595ea261"
        rev = 1
        author = "FireEye"
    strings:
        $create_window = { 41 B9 00 00 CF 00 [4-40] 33 C9 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 FF 15 }
        $keys_check = { B9 14 00 00 00 FF 15 [4-8] B9 10 00 00 00 FF 15 [4] BE 00 80 FF FF 66 85 C6 75 ?? B9 A0 00 00 00 FF 15 [4] 66 85 C6 75 ?? B9 A1 00 00 00 FF 15 [4] 66 85 C6 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_LUALOADER_1
{
    meta:
        author = "FireEye"
    strings:
        $sb1 = { 1? 72 [4] 14 D0 [2] 00 02 28 [2] 00 0A 1? 8D [2] 00 01 13 ?? 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 28 [2] 00 0A 28 [2] 00 0A 80 [2] 00 04 7E [2] 00 04 7B [2] 00 0A 7E [2] 00 04 11 ?? 11 ?? 6F [2] 00 0A 6F [2] 00 0A }
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_LUALOADER_2
{
    meta:
        author = "FireEye"
    strings:
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
        $ss6 = "\x00LoadLibrary\x00"
        $ss7 = "\x00GetProcAddress\x00"
        $ss8 = "\x00VirtualProtect\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_PGF_1
{
    meta:
        date_created = "2020-11-24"
        date_modified = "2020-11-24"
        description = "base.cs"
        md5 = "a495c6d11ff3f525915345fb762f8047"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
        md5 = "7c2a06ceb29cdb25f24c06f2a8892fba"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "\x00ScriptObjectStackTop\x00"
        $ss3 = "\x00Microsoft.JScript\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule FE_APT_Loader_MSIL_REVOLVER_1
{
    meta:
        author = "FireEye"
    strings:
        $inject = { 28 [2] 00 06 0? 0? 7B [2] 00 04 7E [2] 00 0A 28 [2] 00 0A [2-40] 7E [2] 00 0A 0? 20 00 10 00 00 28 [2] 00 0A 0? 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? ?? 20 00 30 00 00 1F 40 28 [2] 00 06 [2-40] 28 [2] 00 0A 1? 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 1? ?? FE 15 [2] 00 02 1? ?? 72 [2] 00 70 28 [2] 00 06 1? ?? FE 15 [2] 00 02 1? ?? 1? ?? 1? 28 [2] 00 06 2? 7E [2] 00 0A 1? ?? 0? 7B [2] 00 04 1? ?? 1? 1? ?? 28 [2] 00 06 2? ?? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-10] 7E [2] 00 0A 1? ?? 1? ?? 20 [2] 1F 00 7E [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? 1? 20 [2] 00 00 20 [2] 00 00 7E [2] 00 0A 28 [2] 00 06 2? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-40] 1? ?? 0? 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 2? ?? 2? 1? 1? ?? 1? ?? 1? ?? 28 [2] 00 06 }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_TRIMBISHOP_1
{
    meta:
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_TRIMBISHOP_2
{
    meta:
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "c0598321d4ad4cf1219cc4f84bad4094"
        rev = 1
        author = "FireEye"
    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_WILDCHILD_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "6f04a93753ae3ae043203437832363c4"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "\x00QueueUserAPC\x00"
        $s2 = "\x00WriteProcessMemory\x00"
        $sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Raw32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4022baddfda3858a57c9cbb0d49f6f86"
        rev = 1
        author = "FireEye"
    strings:
        $load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Raw64_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
        rev = 1
        author = "FireEye"
    strings:
        $load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_DShell_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_DShell_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "590d98bb74879b52b97d8a158af912af"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
        $ss4 = "C:\\Users\\config.ini" fullword
        $ss5 = "Invalid config file" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_DShell_3
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_PGF_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "383161e4deaf7eb2ebeda2c5e9c3204c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A ?? FF 15 [4-32] 8A ?? 04 [0-32] 8B ?? 89 ?? 8B [2] 89 [2] 8B [2] 89 ?? 08 8B [2] 89 [2] 8B [2] 89 [2-64] 8B [5] 83 ?? 01 89 [5] 83 [5-32] 0F B6 [1-2] 0F B6 [1-2] 33 [1-16] 88 ?? EB }
        $sb2 = { 6A 40 [0-32] 68 00 30 00 00 [0-32] 6A 00 [0-16] FF 15 [4-32] 89 45 [4-64] E8 [4-32] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [2-64] FF ( D? | 55 ) }
        $sb3 = { 8B ?? 08 03 ?? 3C [2-32] 0F B? ?? 14 [0-32] 8D [2] 18 [2-64] 0F B? ?? 06 [3-64] 6B ?? 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "04eb45f8546e052fe348fda2425b058c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A ?? FF 15 [4-16] 8A ?? 04 [0-16] 8B ?? 1C [0-64] 0F 10 ?? 66 0F EF C8 0F 11 [0-32] 30 [2] 8D [2] 4? 83 [2] 7? }
        $sb2 = { 8B ?? 08 [0-16] 6A 40 68 00 30 00 00 5? 6A 00 [0-32] FF 15 [4-32] 5? [0-16] E8 [4-64] C1 ?? 04 [0-32] 8A [2] 3? [2] 4? 3? ?? 24 ?? 7? }
        $sb3 = { 8B ?? 3C [0-16] 03 [1-64] 0F B? ?? 14 [0-32] 83 ?? 18 [0-32] 66 3? ?? 06 [4-32] 68 [4] 5? FF 15 [4-16] 85 C0 [2-32] 83 ?? 28 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_PGF_3
{
    meta:
        description = "PGF payload, generated rule based on symfunc/c02594972dbab6d489b46c5dee059e66. Identifies dllmain_hook x86 payloads."
        md5 = "4414953fa397a41156f6fa4f9462d207"
        rev = 4
        author = "FireEye"
    strings:
        $cond1 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF 90 EE 01 6D C7 85 30 F9 FF FF 6C FE 01 6D 8D 85 34 F9 FF FF 89 28 BA CC 19 00 6D 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BB A6 00 00 A1 48 A1 05 6D C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B8 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 56 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 DF B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 52 0B 01 00 A1 4C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 51 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 EF AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 82 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 84 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 2C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 0C 40 05 6D A1 5C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 18 40 05 6D 89 04 24 A1 60 A1 05 6D FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 54 A1 05 6D FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 9C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 00 6D 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 00 6D 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 5D BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 48 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A0 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 FD BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 75 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 76 A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond2 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF B0 EF 3D 6A C7 85 30 F9 FF FF 8C FF 3D 6A 8D 85 34 F9 FF FF 89 28 BA F4 1A 3C 6A 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 B3 A6 00 00 A1 64 A1 41 6A C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B0 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 4E 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 D7 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 4A 0B 01 00 A1 68 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 49 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 E7 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 7A FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 7C AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 62 40 41 6A A1 78 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 6E 40 41 6A 89 04 24 A1 7C A1 41 6A FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 41 6A FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 3C 6A 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 3C 6A 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 55 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 40 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 98 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 F5 BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 6D A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 6E A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond3 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF F0 EF D5 63 C7 85 30 F9 FF FF CC FF D5 63 8D 85 34 F9 FF FF 89 28 BA 28 1B D4 63 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BF A6 00 00 A1 64 A1 D9 63 C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 BC AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 5A 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 E3 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 56 0B 01 00 A1 68 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 55 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 F3 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 86 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 88 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 7E 40 D9 63 A1 7C A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 8A 40 D9 63 89 04 24 A1 80 A1 D9 63 FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 D9 63 FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 D4 63 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 D4 63 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 61 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 4C 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A4 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 01 BC 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 79 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 7A A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond4 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? 90 EE 01 6D C7 85 ?? ?? ?? ?? 6C FE 01 6D 8D 85 ?? ?? ?? ?? 89 28 BA CC 19 00 6D 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 0C 40 05 6D A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 18 40 05 6D 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 00 6D 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 00 6D 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
        $cond5 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? B0 EF 3D 6A C7 85 ?? ?? ?? ?? 8C FF 3D 6A 8D 85 ?? ?? ?? ?? 89 28 BA F4 1A 3C 6A 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 62 40 41 6A A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 6E 40 41 6A 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 3C 6A 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 3C 6A 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
        $cond6 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? F0 EF D5 63 C7 85 ?? ?? ?? ?? CC FF D5 63 8D 85 ?? ?? ?? ?? 89 28 BA 28 1B D4 63 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 7E 40 D9 63 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 8A 40 D9 63 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 D4 63 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 D4 63 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_PGF_4
{
    meta:
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "4414953fa397a41156f6fa4f9462d207"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
        $sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_PGF_5
{
    meta:
        description = "PGF payload, generated rule based on symfunc/a86b004b5005c0bcdbd48177b5bac7b8"
        md5 = "8c91a27bbdbe9fb0877daccd28bd7bb5"
        rev = 3
        author = "FireEye"
    strings:
        $cond1 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 10 30 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 5C 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 00 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
        $cond2 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 20 33 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 58 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 2C 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
        $cond3 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 68 03 01 00 00 6A 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 ?? 00 00 00 00 C6 45 ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 9C 10 00 10 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 6A 14 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 ?? 8B 45 ?? 8A 48 ?? 88 4D ?? 8B 55 ?? 83 C2 0C 8B 45 ?? 8B 0A 89 08 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 52 ?? 89 50 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 83 C0 01 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 14 7D ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 11 0F B6 45 ?? 33 D0 8B 4D ?? 03 8D ?? ?? ?? ?? 88 11 EB ?? 8B 55 ?? 8B 42 ?? 89 45 ?? 6A 40 68 00 30 00 00 8B 4D ?? 51 6A 00 FF 15 ?? ?? ?? ?? 89 45 ?? 8B 55 ?? 52 8B 45 ?? 83 C0 20 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 83 C2 01 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 73 ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 09 8B 85 ?? ?? ?? ?? 99 BE 14 00 00 00 F7 FE 8B 45 ?? 0F B6 14 10 33 CA 8B 45 ?? 03 85 ?? ?? ?? ?? 88 08 EB ?? 8B 4D ?? 89 4D ?? FF 55 ?? 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
        $cond4 = { 8B FF 55 8B EC 81 EC 3? ?1 ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 E0 56 C7 45 F8 ?? ?? ?? ?? C6 85 D8 FE FF FF ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 D9 FE FF FF 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 F4 ?? ?? ?? ?? C6 45 E7 ?? C7 45 E8 ?? ?? ?? ?? C7 45 EC ?? ?? ?? ?? C7 45 FC ?? ?? ?? ?? C7 45 F? ?? ?? ?? ?0 6A ?? 6A ?? 8D 8D D8 FE FF FF 51 6A ?? 68 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 F8 6A ?? FF ?? ?? ?? ?? ?? 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 ?? ?? 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF ?? ?? ?? ?? EB ?? 8B 85 D4 FE FF FF 83 C? ?1 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D ?? 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB ?? 8B 55 F8 8B 42 08 89 45 FC 6A ?? 68 ?? ?? ?? ?? 8B 4D FC 51 6A ?? FF ?? ?? ?? ?? ?? 89 45 EC 8B 55 FC 52 8B 45 F8 83 ?? ?? 50 8B 4D EC 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 D0 FE FF FF ?? ?? ?? ?? EB ?? 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 ?? 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE ?? ?? ?? ?? F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB ?? 8B 4D EC 89 4D F0 FF ?? ?? 5E 8B 4D E0 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "01d68343ac46db6065f888a094edfe4f"
        rev = 1
        author = "FireEye"
    strings:
        $alloc_n_load = { 6A 40 68 00 30 00 00 [0-20] 6A 00 [0-20] FF D0 [4-60] F3 A4 [30-100] 6B C0 28 8B 4D ?? 8B 4C 01 10 8B 55 ?? 6B D2 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_REDFLARE_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4e7e90c7147ee8aa01275894734f4492"
        rev = 1
        author = "FireEye"
    strings:
        $inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
        $sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
        $sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_MATRYOSHKA_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka.rs"
        md5 = "7f8102b789303b7861a03290c79feba0"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
        $sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
        $si1 = "CreateToolhelp32Snapshot" fullword
        $si2 = "Process32Next" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "2b686a8b83f8e1d8b455976ae70dab6e"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
        $sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
        $sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "4326a7e863928ffbb5f6bdf63bb9126e"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
        $sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
        $sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_3
{
    meta:
        description = "PGF payload, generated rule based on symfunc/8a2f2236fdfaa3583ab89076025c6269. Identifies dllmain_hook x64 payloads."
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        rev = 4
        author = "FireEye"
    strings:
        $cond1 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 80 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 5A B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 E9 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AC 96 01 00 48 8D 45 AF 48 89 C1 E8 F0 FE 00 00 48 8B 05 25 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6B B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 AA B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 61 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 4F B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 20 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 0E C8 05 00 48 8B 05 69 8A 06 00 FF D0 48 8D 15 0A C8 05 00 48 89 C1 48 8B 05 5E 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 19 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 01 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 E0 F9 FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 87 F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CB 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 37 FC 00 00 48 89 D8 48 89 C1 E8 4C AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9A 9C 01 00 48 89 D8 48 89 C1 E8 2F AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond2 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 ?? ?? ?? ?? FF D0 48 89 C1 48 8D 85 ?? ?? ?? ?? 41 B8 04 01 00 00 48 89 C2 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8D 4D ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 49 89 C8 48 89 C1 E8 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 89 C2 B9 08 00 00 00 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 38 04 00 00 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 48 8D 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 41 B8 00 00 00 00 48 89 C1 E8 ?? ?? ?? ?? 48 83 F8 FF 0F 95 C0 84 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? EB ?? 48 8B 45 ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 48 8D 15 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 89 45 ?? 48 89 E8 48 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 C7 45 ?? 00 00 00 00 48 8B 55 ?? 48 8B 85 ?? ?? ?? ?? 48 39 C2 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 73 ?? 48 8B 45 ?? 48 8B 00 48 8B 55 ?? 48 81 C2 00 10 00 00 48 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 8B 4D ?? 48 8B 55 ?? 48 01 CA 48 39 D0 0F 83 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 8B 45 ?? 48 8B 00 48 8D 95 ?? ?? ?? ?? 41 B8 30 00 00 00 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 48 8B 45 ?? 48 8B 00 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 00 00 00 00 EB ?? 90 EB ?? 90 48 83 45 ?? 08 E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 48 63 D0 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 89 C2 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 01 00 00 00 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 FB 01 EB ?? 48 89 C3 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond3 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 C1 7C 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 33 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 B2 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 75 96 01 00 48 8D 45 AF 48 89 C1 E8 B9 FE 00 00 48 8B 05 66 7C 06 00 FF D0 89 C2 B9 08 00 00 00 E8 3C B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 83 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 2A F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 28 B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 69 7B 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 11 B9 05 00 48 8B 05 A2 7B 06 00 FF D0 48 8D 15 0D B9 05 00 48 89 C1 48 8B 05 97 7B 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 5A 7B 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 22 7B 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 59 FB FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 00 FB FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 94 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 00 FC 00 00 48 89 D8 48 89 C1 E8 45 AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 63 9C 01 00 48 89 D8 48 89 C1 E8 28 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond4 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 D3 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 65 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 EC FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AF 96 01 00 48 8D 45 AF 48 89 C1 E8 F3 FE 00 00 48 8B 05 78 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6E B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 B5 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 64 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 5A B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 73 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 45 C8 05 00 48 8B 05 B4 8A 06 00 FF D0 48 8D 15 41 C8 05 00 48 89 C1 48 8B 05 A9 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 6C 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 54 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 33 FA FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 DA F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CE 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 3A FC 00 00 48 89 D8 48 89 C1 E8 4F AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9D 9C 01 00 48 89 D8 48 89 C1 E8 32 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_4
{
    meta:
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
        $sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_5
{
    meta:
        description = "PGF payload, generated rule based on symfunc/8167a6d94baca72bac554299d7c7f83c"
        md5 = "150224a0ccabce79f963795bf29ec75b"
        rev = 3
        author = "FireEye"
    strings:
        $cond1 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 13 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 66 23 00 00 48 8B 4C 24 40 FF 15 EB F9 FF FF B8 01 00 00 00 48 83 C4 38 C3 }
        $cond2 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 A3 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 F6 20 00 00 48 8B 4C 24 40 FF 15 7B FA FF FF B8 01 00 00 00 48 83 C4 38 C3 }
        $cond3 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? 8B 44 24 48 89 44 24 20 83 7C 24 2? ?1 74 ?? EB ?? 48 8B 44 24 40 48 ?? ?? ?? ?? ?? ?? 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? 48 83 C4 38 C3 }
        $cond4 = { 4C 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 48 83 EC 38 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 83 7C 24 ?? 01 74 ?? EB ?? 48 8B 44 24 ?? 48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 38 C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "f20824fa6e5c81e3804419f108445368"
        rev = 1
        author = "FireEye"
    strings:
        $alloc_n_load = { 41 B9 40 00 00 00 41 B8 00 30 00 00 33 C9 [1-10] FF 50 [4-80] F3 A4 [30-120] 48 6B C9 28 [3-20] 48 6B C9 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_REDFLARE_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d"
        rev = 1
        author = "FireEye"
    strings:
        $alloc = { 45 8B C0 33 D2 [2-6] 00 10 00 00 [2-6] 04 00 00 00 [1-6] FF 15 [4-60] FF 15 [4] 85 C0 [4-40] 20 00 00 00 [4-40] FF 15 [4] 85 C0 }
        $inject = { 83 F8 01 [2-20] 33 C0 45 33 C9 [3-10] 45 33 C0 [3-10] 33 D2 [30-100] FF 15 [4] 85 C0 [20-100] 01 00 10 00 [0-10] FF 15 [4] 85 C0 [4-30] FF 15 [4] 85 C0 [2-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "ZwQueryInformationProcess" fullword
        $s2 = "WriteProcessMemory" fullword
        $s3 = "CreateProcessW" fullword
        $s4 = "WriteProcessMemory" fullword
        $s5 = "\x00Invalid NT Signature!\x00"
        $s6 = "\x00Error while creating and mapping section. NTStatus: "
        $s7 = "\x00Error no process information - NTSTATUS:"
        $s8 = "\x00Error while erasing pe header. NTStatus: "
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win_PGF_1
{
    meta:
        description = "PDB string used in some PGF DLL samples"
        md5 = "013c7708f1343d684e3571453261b586"
        rev = 6
        author = "FireEye"
    strings:
        $pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
        $pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\Release\\DllSource\.pdb\x00/ nocase
        $pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win_PGF_2
{
    meta:
        description = "PE rich header matches PGF backdoor"
        md5 = "226b1ac427eb5a4dc2a00cc72c163214"
        md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
        md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
        md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
        rev = 4
        author = "FireEye"
    strings:
        $rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
        $rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
        $rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
        $rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and (($rich1 at 128) or ($rich2 at 128) or ($rich3 at 128) or ($rich4 at 128))
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Linux_REDFLARE_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "find_applet_by_name" fullword
        $s2 = "bb_basename" fullword
        $s3 = "hk_printf_chk" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d,4e7e90c7147ee8aa01275894734f4492"
        rev = 3
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "runCommand" fullword
        $3 = "stop" fullword
        $4 = "fini" fullword
        $5 = "VirtualAllocEx" fullword
        $6 = "WriteProcessMemory" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
        rev = 2
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "Cookie: SID1=%s" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_3
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
        rev = 1
        author = "FireEye"
    strings:
        $calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
        $str1 = "CreateCompatibleBitmap" fullword
        $str2 = "BitBlt" fullword
        $str3 = "runCommand" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_4
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "LogonUserW" fullword
        $s2 = "ImpersonateLoggedOnUser" fullword
        $s3 = "runCommand" fullword
        $user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_5
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "AdjustTokenPrivileges" fullword
        $s2 = "LookupPrivilegeValueW" fullword
        $s3 = "ImpersonateLoggedOnUser" fullword
        $s4 = "runCommand" fullword
        $steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_6
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "RevertToSelf" fullword
        $s2 = "Unsuccessful" fullword
        $s3 = "Successful" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_7
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "NamedPipe"
        $named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_8
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "PSRunner.PSRunner" fullword
        $2 = "CorBindToRuntime" fullword
        $3 = "ReportEventW" fullword
        $4 = "InvokePS" fullword wide
        $5 = "runCommand" fullword
        $6 = "initialize" fullword
        $trap = { 03 40 00 80 E8 [4] CC }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Builder_MSIL_G2JS_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the Gadget2JScript project."
        md5 = "fa255fdc88ab656ad9bc383f9b322a76"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid1 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Builder_MSIL_SharpGenerator_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGenerator' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "3f450977-d796-4016-bb78-c9e91c6a0f08" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Builder_MSIL_SinfulOffice_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SinfulOffice' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "9940e18f-e3c7-450f-801a-07dd534ccb9a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_ADPassHunt_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid = "15745B9E-A059-4AF1-A0D8-863E349CD85D" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_ADPassHunt_2
{
    meta:
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1
        author = "FireEye"
    strings:
        $pdb1 = "\\ADPassHunt\\"
        $pdb2 = "\\ADPassHunt.pdb"
        $s1 = "Usage: .\\ADPassHunt.exe"
        $s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
        $s3 = "[ADA] Searching for accounts with userpassword attribute"
        $s4 = "[GPP] Searching for passwords now"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ((@pdb2[1] < @pdb1[1] + 50) or 2 of ($s*))
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_CredSnatcher_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CredSnatcher' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "370b4d21-09d0-433f-b7e4-4ebdd79948ec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_TitoSpecial_1
{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4
        author = "FireEye"
    strings:
        $str1 = "Minidump" ascii wide
        $str2 = "dumpType" ascii wide
        $str3 = "WriteProcessMemory" ascii wide
        $str4 = "bInheritHandle" ascii wide
        $str5 = "GetProcessById" ascii wide
        $str6 = "SafeHandle" ascii wide
        $str7 = "BeginInvoke" ascii wide
        $str8 = "EndInvoke" ascii wide
        $str9 = "ConsoleApplication1" ascii wide
        $str10 = "getOSInfo" ascii wide
        $str11 = "OpenProcess" ascii wide
        $str12 = "LoadLibrary" ascii wide
        $str13 = "GetProcAddress" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($str*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_TitoSpecial_2
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid1 = "C6D94B4C-B063-4DEB-A83A-397BA08515D3" ascii nocase wide
        $typelibguid2 = "3b5320cf-74c1-494e-b2c8-a94a24380e60" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ($typelibguid1 or $typelibguid2)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_WCMDump_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WCMDump' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "21e322f2-4586-4aeb-b1ed-d240e2a79e19" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_Win_EXCAVATOR_1
{
    meta:
        description = "This rule looks for the binary signature of the 'Inject' method found in the main Excavator PE."
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        rev = 4
        author = "FireEye"
    strings:
        $bytes1 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 20 01 00 00 48 8B 05 75 BF 01 00 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 8D 0D 12 A1 01 00 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 00 FF 15 CB 1F 01 00 48 85 C0 75 1B FF 15 80 1F 01 00 8B D0 48 8D 0D DF A0 01 00 E8 1A FF FF FF 33 C0 E9 B4 02 00 00 48 8D 15 D4 A0 01 00 48 89 9C 24 30 01 00 00 48 8B C8 FF 15 4B 1F 01 00 48 8B D8 48 85 C0 75 19 FF 15 45 1F 01 00 8B D0 48 8D 0D A4 A0 01 00 E8 DF FE FF FF E9 71 02 00 00 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 45 66 66 0F 1F 84 00 00 00 00 00 48 8B 4C 24 60 FF 15 4D 1F 01 00 3B C6 74 22 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 D1 EB 0A 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A0 01 00 48 8D 05 A6 C8 01 00 B9 C8 05 00 00 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 B2 FF 15 CC 1E 01 00 4C 8D 44 24 78 BA 0A 00 00 00 48 8B C8 FF 15 01 1E 01 00 85 C0 0F 84 66 01 00 00 48 8B 4C 24 78 48 8D 45 80 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 D8 1D 01 00 85 C0 0F 84 35 01 00 00 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 50 01 FF 15 5C 1E 01 00 FF 15 06 1E 01 00 4C 8B 44 24 68 33 D2 48 8B C8 FF 15 DE 1D 01 00 48 8B F8 48 85 C0 0F 84 FF 00 00 00 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 50 01 FF 15 25 1E 01 00 85 C0 0F 84 E2 00 00 00 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 6C 1D 01 00 85 C0 0F 84 B1 00 00 00 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C 8D 05 58 39 03 00 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 44 24 30 04 00 08 00 44 89 74 24 28 4C 89 74 24 20 FF 15 0C 1D 01 00 85 C0 74 65 48 8B 4C 24 70 8B 5D 98 FF 15 1A 1D 01 00 48 8B 4D 88 FF 15 10 1D 01 00 48 8B 4D 90 FF 15 06 1D 01 00 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 4E 1D 01 00 48 8B D8 48 85 C0 74 2B 48 8B C8 E8 4E 06 00 00 48 85 C0 74 1E BA FF FF FF FF 48 8B C8 FF 15 3B 1D 01 00 48 8B CB FF 15 CA 1C 01 00 B8 01 00 00 00 EB 24 FF 15 DD 1C 01 00 8B D0 48 8D 0D 58 9E 01 00 E8 77 FC FF FF 48 85 FF 74 09 48 8B CF FF 15 A9 1C 01 00 33 C0 48 8B 9C 24 30 01 00 00 48 8B 4D 10 48 33 CC E8 03 07 00 00 4C 8D 9C 24 20 01 00 00 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes2 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes3 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes4 = { 48 89 74 24 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 55 48 8D 6C 24 ?? 48 81 EC 20 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 ?? 48 8D 0D ?? ?? ?? ?? 4C 89 74 24 ?? 0F 11 45 ?? 41 8B FE 4C 89 74 24 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? FF 15 ?? ?? ?? ?? 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 66 0F 1F 84 00 ?? ?? 00 00 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 ?? 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 01 00 48 8D 05 ?? ?? ?? ?? B9 C8 05 00 00 90 F3 0F 6F 40 ?? 48 8D 40 ?? 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? F3 0F 6F 40 ?? 66 0F EF C2 F3 0F 7F 40 ?? 48 83 E9 01 75 ?? FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 45 ?? 41 B9 02 00 00 00 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 02 00 00 00 41 8D 51 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 4C 8B 44 24 ?? 33 D2 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 48 8B C8 41 8D 50 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 ?? 4C 8D 4C 24 ?? 4C 89 74 24 ?? 33 D2 41 B8 00 00 02 00 48 C7 44 24 ?? 08 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 45 ?? 48 89 44 24 ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 45 ?? 48 89 7D ?? 48 89 44 24 ?? 45 33 C9 4C 89 74 24 ?? 33 D2 4C 89 74 24 ?? C7 44 24 ?? 04 00 08 00 44 89 74 24 ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 8B 5D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA FF FF FF FF 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF 15 ?? ?? ?? ?? 33 C0 48 8B 9C 24 ?? ?? ?? ?? 48 8B 4D ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 73 ?? 49 8B 7B ?? 4D 8B 73 ?? 49 8B E3 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_Win_EXCAVATOR_2
{
    meta:
        description = "This rule looks for the binary signature of the routine that calls PssFreeSnapshot found in the Excavator-Reflector DLL."
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3
        author = "FireEye"
    strings:
        $bytes1 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A0 01 00 00 48 8B 05 4C 4A 01 00 48 33 C4 48 89 85 90 00 00 00 BA 50 00 00 00 C7 05 CB 65 01 00 43 00 3A 00 66 89 15 EC 65 01 00 4C 8D 44 24 68 48 8D 15 D8 68 01 00 C7 05 B2 65 01 00 5C 00 57 00 33 C9 C7 05 AA 65 01 00 69 00 6E 00 C7 05 A4 65 01 00 64 00 6F 00 C7 05 9E 65 01 00 77 00 73 00 C7 05 98 65 01 00 5C 00 4D 00 C7 05 92 65 01 00 45 00 4D 00 C7 05 8C 65 01 00 4F 00 52 00 C7 05 86 65 01 00 59 00 2E 00 C7 05 80 65 01 00 44 00 4D 00 C7 05 72 68 01 00 53 00 65 00 C7 05 6C 68 01 00 44 00 65 00 C7 05 66 68 01 00 42 00 75 00 C7 05 60 68 01 00 47 00 50 00 C7 05 5A 68 01 00 72 00 69 00 C7 05 54 68 01 00 56 00 69 00 C7 05 4E 68 01 00 4C 00 45 00 C7 05 48 68 01 00 67 00 65 00 C7 05 12 67 01 00 6C 73 61 73 C7 05 0C 67 01 00 73 2E 65 78 C6 05 09 67 01 00 65 FF 15 63 B9 00 00 45 33 F6 85 C0 74 66 48 8B 44 24 68 48 89 44 24 74 C7 44 24 70 01 00 00 00 C7 44 24 7C 02 00 00 00 FF 15 A4 B9 00 00 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF 15 1A B9 00 00 85 C0 74 30 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF 15 EF B8 00 00 FF 15 11 B9 00 00 48 8B 4C 24 48 FF 15 16 B9 00 00 48 89 9C 24 B0 01 00 00 48 8D 0D BF 2E 01 00 48 89 B4 24 B8 01 00 00 4C 89 74 24 40 FF 15 1C B9 00 00 48 85 C0 0F 84 B0 00 00 00 48 8D 15 AC 2E 01 00 48 8B C8 FF 15 1B B9 00 00 48 8B D8 48 85 C0 0F 84 94 00 00 00 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 06 15 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 63 66 0F 1F 44 00 00 48 8B 4C 24 40 4C 8D 45 80 41 B9 04 01 00 00 33 D2 FF 15 89 B8 00 00 48 8D 15 F2 65 01 00 48 8D 4D 80 E8 49 0F 00 00 48 85 C0 75 38 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 A3 14 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 A3 33 C0 E9 F5 00 00 00 48 8B 5C 24 40 48 8B CB FF 15 5E B8 00 00 8B F0 48 85 DB 74 E4 85 C0 74 E0 4C 8D 4C 24 50 48 89 BC 24 C0 01 00 00 BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 12 B8 00 00 85 C0 0F 85 A0 00 00 00 48 8D 05 43 FD FF FF 4C 89 74 24 30 C7 44 24 28 80 00 00 00 48 8D 0D 3F 63 01 00 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 4C 89 74 24 60 FF 15 E4 B7 00 00 48 8B F8 48 83 F8 FF 74 59 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 00 00 00 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF 15 B1 B9 00 00 48 8B CB FF 15 78 B7 00 00 48 8B CF FF 15 6F B7 00 00 FF 15 B1 B7 00 00 48 8B 54 24 50 48 8B C8 FF 15 53 B7 00 00 33 C9 FF 15 63 B7 00 00 CC 48 8B CB FF 15 49 B7 00 00 48 8B BC 24 C0 01 00 00 33 C0 48 8B B4 24 B8 01 00 00 48 8B 9C 24 B0 01 00 00 48 8B 8D 90 00 00 00 48 33 CC E8 28 00 00 00 4C 8B B4 24 C8 01 00 00 48 81 C4 A0 01 00 00 5D C3 }
        $bytes2 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes3 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes4 = { 4C 89 74 24 ?? 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC A0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? BA 50 00 00 00 C7 05 ?? ?? ?? ?? 43 00 3A 00 66 89 15 ?? ?? 01 00 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 5C 00 57 00 33 C9 C7 05 ?? ?? ?? ?? 69 00 6E 00 C7 05 ?? ?? ?? ?? 64 00 6F 00 C7 05 ?? ?? ?? ?? 77 00 73 00 C7 05 ?? ?? ?? ?? 5C 00 4D 00 C7 05 ?? ?? ?? ?? 45 00 4D 00 C7 05 ?? ?? ?? ?? 4F 00 52 00 C7 05 ?? ?? ?? ?? 59 00 2E 00 C7 05 ?? ?? ?? ?? 44 00 4D 00 C7 05 ?? ?? ?? ?? 53 00 65 00 C7 05 ?? ?? ?? ?? 44 00 65 00 C7 05 ?? ?? ?? ?? 42 00 75 00 C7 05 ?? ?? ?? ?? 47 00 50 00 C7 05 ?? ?? ?? ?? 72 00 69 00 C7 05 ?? ?? ?? ?? 56 00 69 00 C7 05 ?? ?? ?? ?? 4C 00 45 00 C7 05 ?? ?? ?? ?? 67 00 65 00 C7 05 ?? ?? ?? ?? 6C 73 61 73 C7 05 ?? ?? ?? ?? 73 2E 65 78 C6 05 ?? ?? ?? ?? 65 FF 15 ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 ?? 48 89 44 24 ?? C7 44 24 ?? 01 00 00 00 C7 44 24 ?? 02 00 00 00 FF 15 ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 ?? 41 8D 56 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 44 24 ?? 4C 89 74 24 ?? 45 33 C9 33 D2 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 0F 1F 44 00 ?? 48 8B 4C 24 ?? 4C 8D 45 ?? 41 B9 04 01 00 00 33 D2 FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B CB FF 15 ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 ?? 48 89 BC 24 ?? ?? ?? ?? BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 89 74 24 ?? C7 44 24 ?? 80 00 00 00 48 8D 0D ?? ?? ?? ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 01 00 00 00 BA 00 00 00 10 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 ?? 41 B9 02 00 00 00 4C 89 74 24 ?? 4C 8B C7 8B D6 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 54 24 ?? 48 8B C8 FF 15 ?? ?? ?? ?? 33 C9 FF 15 ?? ?? ?? ?? CC 48 8B CB FF 15 ?? ?? ?? ?? 48 8B BC 24 ?? ?? ?? ?? 33 C0 48 8B B4 24 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 ?? ?? ?? ?? 48 81 C4 A0 01 00 00 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Dropper_HTA_WildChild_1
{
    meta:
        description = "This rule looks for strings present in unobfuscated HTAs generated by the WildChild builder."
        md5 = "3e61ca5057633459e96897f79970a46d"
        rev = 5
        author = "FireEye"
    strings:
        $s1 = "processpath" ascii wide
        $s2 = "v4.0.30319" ascii wide
        $s3 = "v2.0.50727" ascii wide
        $s4 = "COMPLUS_Version" ascii wide
        $s5 = "FromBase64Transform" ascii wide
        $s6 = "MemoryStream" ascii wide
        $s7 = "entry_class" ascii wide
        $s8 = "DynamicInvoke" ascii wide
        $s9 = "Sendoff" ascii wide
        $script_header = "<script language=" ascii wide
    condition:
        $script_header at 0 and all of ($s*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Dropper_LNK_LNKSmasher_1
{
    meta:
        description = "The LNKSmasher project contains a prebuilt LNK file that has pieces added based on various configuration items. Because of this, several artifacts are present in every single LNK file generated by LNKSmasher, including the Drive Serial #, the File Droid GUID, and the GUID CLSID."
        md5 = "0a86d64c3b25aa45428e94b6e0be3e08"
        rev = 6
        author = "FireEye"
    strings:
        $drive_serial = { 12 F7 26 BE }
        $file_droid_guid = { BC 96 28 4F 0A 46 54 42 81 B8 9F 48 64 D7 E9 A5 }
        $guid_clsid = { E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D }
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        $header at 0 and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_CoreHound_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CoreHound' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "1fff2aee-a540-4613-94ee-4f208b30c599" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_GETDOMAINPASSWORDPOLICY_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the recon utility 'getdomainpasswordpolicy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid0 = "a5da1897-29aa-45f4-a924-561804276f08" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_HOLSTER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the a customized version of the 'DUEDLLIGENCE' project."
        md5 = "a91bf61cc18705be2288a0f6f125068f"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid1 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_INVEIGHZERO_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'inveighzero' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "113ae281-d1e5-42e7-9cc2-12d30757baf1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_KeeFarce_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeeFarce' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "17589ea6-fcc9-44bb-92ad-d5b3eea6af03" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_KeePersist_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeePersist' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "1df47db2-7bb8-47c2-9d85-5f8d3f04a884" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PrepShellcode_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'PrepShellcode' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "d16ed275-70d5-4ae5-8ce7-d249f967616c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PuppyHound_1
{
    meta:
        description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 6
        author = "FireEye"
    strings:
        $1 = "PuppyHound"
        $2 = "UserDomainKey"
        $3 = "LdapBuilder"
        $init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
        $msil = /\x00_Cor(Exe|Dll)Main\x00/
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PXELOOT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
        md5 = "82e33011ac34adfcced6cddc8ea56a81"
        rev = 7
        author = "FireEye"
    strings:
        $typelibguid1 = "78B2197B-2E56-425A-9585-56EDC2C797D6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PXELOOT_2
{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the PXE And Loot code."
        md5 = "d93100fe60c342e9e3b13150fd91c7d8"
        rev = 5
        author = "FireEye"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "PXE" ascii nocase wide
        $str2 = "InvestigateRPC" ascii nocase wide
        $str3 = "DhcpRecon" ascii nocase wide
        $str4 = "UnMountWim" ascii nocase wide
        $str5 = "remote WIM image" ascii nocase wide
        $str6 = "DISMWrapper" ascii nocase wide
        $str7 = "findTFTPServer" ascii nocase wide
        $str8 = "DHCPRequestRecon" ascii nocase wide
        $str9 = "DHCPDiscoverRecon" ascii nocase wide
        $str10 = "GoodieFile" ascii nocase wide
        $str11 = "InfoStore" ascii nocase wide
        $str12 = "execute" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_Rubeus_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
        md5 = "66e0681a500c726ed52e5ea9423d2654"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SAFETYKATZ_4
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SafetyKatz project."
        md5 = "45736deb14f3a68e88b038183c23e597"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid1 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SEATBELT_1
{
    meta:
        description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
        md5 = "848837b83865f3854801be1f25cb9f4d"
        rev = 3
        author = "FireEye"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
        $str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
        $str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
        $str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
        $str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
        $str6 = "*[System/EventID={0}]" ascii nocase wide
        $str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
        $str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
        $str9 = "{0}" ascii nocase wide
        $str10 = "{0,-23}" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SEATBELT_2
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SeatBelt project."
        md5 = "9f401176a9dd18fa2b5b90b4a2aa1356"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid1 = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPersist_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPersist project."
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid1 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPersist_2
{
    meta:
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        rev = 1
        author = "FireEye"
    strings:
        $a1 = "SharPersist.lib"
        $a2 = "SharPersist.exe"
        $b1 = "ERROR: Invalid hotkey location option given." ascii wide
        $b2 = "ERROR: Invalid hotkey given." ascii wide
        $b3 = "ERROR: Keepass configuration file not found." ascii wide
        $b4 = "ERROR: Keepass configuration file was not found." ascii wide
        $b5 = "ERROR: That value already exists in:" ascii wide
        $b6 = "ERROR: Failed to delete hidden registry key." ascii wide
        $pdb1 = "\\SharPersist\\"
        $pdb2 = "\\SharPersist.pdb"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ((@pdb2[1] < @pdb1[1] + 50) or (1 of ($a*) and 2 of ($b*)))
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharpHound_3
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SharpHound3 project."
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid1 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPivot_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
        $s3 = "cmd_rpc" wide
        $s4 = "costura"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPivot_2
{
    meta:
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "costura"
        $s2 = "cmd_schtask" wide
        $s3 = "cmd_wmi" wide
        $s4 = "cmd_rpc" wide
        $s5 = "GoogleUpdateTaskMachineUA" wide
        $s6 = "servicehijack" wide
        $s7 = "poisonhandler" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPivot_3
{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "SharPivot" ascii wide
        $str2 = "ParseArgs" ascii wide
        $str3 = "GenRandomString" ascii wide
        $str4 = "ScheduledTaskExists" ascii wide
        $str5 = "ServiceExists" ascii wide
        $str6 = "lpPassword" ascii wide
        $str7 = "execute" ascii wide
        $str8 = "WinRM" ascii wide
        $str9 = "SchtaskMod" ascii wide
        $str10 = "PoisonHandler" ascii wide
        $str11 = "SCShell" ascii wide
        $str12 = "SchtaskMod" ascii wide
        $str13 = "ServiceHijack" ascii wide
        $str14 = "commandArg" ascii wide
        $str15 = "payloadPath" ascii wide
        $str16 = "Schtask" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPivot_4
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPivot project."
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid1 = "44B83A69-349F-4A3E-8328-A45132A70D62" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharpSchtask_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpSchtask' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "0a64a5f4-bdb6-443c-bdc7-f6f0bf5b5d6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharpStomp_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharpStomp project."
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid1 = "41f35e79-2034-496a-8c82-86443164ada2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SHARPZEROLOGON_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'sharpzerologon' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "15ce9a3c-4609-4184-87b2-e29fc5e2b770" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_WMISharp_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMISharp' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "3a2421d9-c1aa-4fff-ad76-7fcb48ed4bff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_WMIspy_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIspy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "5ee2bca3-01ad-489b-ab1b-bda7962e06bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_PY_ImpacketObfuscation_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        description = "smbexec"
        md5 = "0b1e512afe24c31531d6db6b47bac8ee"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "class CMDEXEC" nocase
        $s2 = "class RemoteShell" nocase
        $s3 = "self.services_names"
        $s4 = "import random"
        $s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
        $s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/
    condition:
        all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_PY_ImpacketObfuscation_2
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        description = "wmiexec"
        md5 = "f3dd8aa567a01098a8a610529d892485"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "import random"
        $s2 = "class WMIEXEC" nocase
        $s3 = "class RemoteShell" nocase
        $s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
        $s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
    condition:
        all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_Win32_AndrewSpecial_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "e89efa88e3fda86be48c0cc8f2ef7230"
        rev = 4
        author = "FireEye"
    strings:
        $dump = { 6A 00 68 FF FF 1F 00 FF 15 [4] 89 45 ?? 83 [2] 00 [1-50] 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 10 68 [4] FF 15 [4] 89 45 [10-70] 6A 00 6A 00 6A 00 6A 02 8B [2-4] 5? 8B [2-4] 5? 8B [2-4] 5? E8 [4-20] FF 15 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
        $shellcode_x86_inline = { C6 45 ?? B8 C6 45 ?? 3C C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 33 C6 45 ?? C9 C6 45 ?? 8D C6 45 ?? 54 C6 45 ?? 24 C6 45 ?? 04 C6 45 ?? 64 C6 45 ?? FF C6 45 ?? 15 C6 45 ?? C0 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 83 C6 45 ?? C4 C6 45 ?? 04 C6 45 ?? C2 C6 45 ?? 14 C6 45 ?? 00 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and $dump and any of ($shellcode*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_Win64_AndrewSpecial_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4456e52f6f8543c3ba76cb25ea3e9bd2"
        rev = 5
        author = "FireEye"
    strings:
        $dump = { 33 D2 B9 FF FF 1F 00 FF 15 [10-90] 00 00 00 00 [2-6] 80 00 00 00 [2-6] 02 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4-120] 00 00 00 00 [2-6] 00 00 00 00 [2-6] 00 00 00 00 41 B9 02 00 00 00 [6-15] E8 [4-20] FF 15 }
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x64_inline = { C6 44 24 ?? 4C C6 44 24 ?? 8B C6 44 24 ?? D1 C6 44 24 ?? B8 C6 44 24 ?? 3C C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 0F C6 44 24 ?? 05 C6 44 24 ?? C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and $dump and any of ($shellcode*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_B64Engine_DotNetToJScript_Dos
{
    meta:
        description = "This file may enclude a Base64 encoded .NET executable. This technique is used by the project DotNetToJScript which is used by many malware families including GadgetToJScript."
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        rev = 1
        author = "FireEye"
    strings:
        $b64_mz = "AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEU"
    condition:
        $b64_mz
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_DotNetToJScript_Functions
{
    meta:
        description = "This file references a selection of functions/classes that are used by the project DotNetToJScript and commonly found in other malware families including GadgetToJScript."
        md5 = "06b6f677d64eef9c4f69ef105b76fba8"
        rev = 1
        author = "FireEye"
    strings:
        $lib1 = "System.Text.ASCIIEncoding"
        $lib2 = "System.Security.Cryptography.FromBase64Transform"
        $lib3 = "System.IO.MemoryStream"
        $lib4 = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
        $vba1 = "Microsoft.XMLDOM"
        $vba2 = "Microsoft.Windows.ActCtx"
        $vba3 = "System.IO.MemoryStream"
        $vba4 = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
    condition:
        all of ($lib*) or all of ($vba*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_GadgetToJScript_1
{
    meta:
        description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        rev = 4
        author = "FireEye"
    strings:
        $s1 = "GF6eU5ldFRvSnNjcmlwdExvYWRl"
        $s2 = "henlOZXRUb0pzY3JpcHRMb2Fk"
        $s3 = "YXp5TmV0VG9Kc2NyaXB0TG9hZGV"
    condition:
        any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_LNK_Win_GenericLauncher
{
    meta:
        date = "09/04/2018"
        description = "Signature to detect LNK files or OLE objects with embedded LNK files and generic launcher commands, except powershell which is large enough to have its own gene"
        md5 = "14dd758e8f89f14612c8df9f862c31e4"
        rev = 7
        author = "FireEye"
    strings:
        $a01 = "cmd.exe /" ascii nocase wide
        $a02 = "cscript" ascii nocase wide
        $a03 = "jscript" ascii nocase wide
        $a04 = "wscript" ascii nocase wide
        $a05 = "wmic" ascii nocase wide
        $a07 = "mshta" ascii nocase wide
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        (($header at 0) or ((uint32(0) == 0xE011CFD0) and $header)) and (1 of ($a*))
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_AllTheThings_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'AllTheThings' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "542ccc64-c4c3-4c03-abcd-199a11b26754" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_CSharpSectionInjection_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'C_Sharp_SectionInjection' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "d77135da-0496-4b5c-9afe-e1590a4c136a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule Loader_MSIL_DUEDLLIGENCE_1
{
    meta:
        author = "FireEye"
    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule Loader_MSIL_DUEDLLIGENCE_2
{
    meta:
        author = "FireEye"
    strings:
        $1 = "DueDLLigence" fullword
        $2 = "CPlApplet" fullword
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule Loader_MSIL_DUEDLLIGENCE_3
{
    meta:
        author = "FireEye"
    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $rc4 = { 20 00 01 00 00 8D [2] 00 01 1? ?? 20 00 01 00 00 8D [2] 00 01 1? ?? 03 8E 69 8D [2] 00 01 1? ?? 16 0B 2B ?? 1? ?? 07 02 07 02 8E 69 5D 91 9E 1? ?? 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 }
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_Generic_1
{
    meta:
        md5 = "b8415b4056c10c15da5bba4826a44ffd"
        rev = 5
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
        $str1 = "DllImportAttribute"
        $str2 = "FromBase64String"
        $str3 = "ResumeThread"
        $str4 = "OpenThread"
        $str5 = "SuspendThread"
        $str6 = "QueueUserAPC"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_InMemoryCompilation_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'In-MemoryCompilation' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "524d2687-0042-4f93-b695-5579f3865205" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_NETAssemblyInject_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NET-Assembly-Inject' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "af09c8c3-b271-4c6c-8f48-d5f0e1d1cac6" ascii nocase wide
        $typelibguid1 = "c5e56650-dfb0-4cd9-8d06-51defdad5da1" ascii nocase wide
        $typelibguid2 = "e8fa7329-8074-4675-9588-d73f88a8b5b6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_NetshShellCodeRunner_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NetshShellCodeRunner' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2
        author = "FireEye"
    strings:
        $typelibguid0 = "49c045bc-59bb-4a00-85c3-4beb59b2ee12" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_RURALBISHOP_1
{
    meta:
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_RURALBISHOP_2
{
    meta:
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1
        author = "FireEye"
    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_RuralBishop_3
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid1 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_SharPy_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharPy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "f6cf1d3b-3e43-4ecf-bb6d-6731610b4866" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_TrimBishop_1
{
    meta:
        description = "This rule looks for .NET PE files that have the string 'msg' more than 60 times as well as numerous function names unique to or used by the TrimBishop tool. All strings found in RuralBishop are reversed in TrimBishop and stored in a variable with the format 'msg##'. With the exception of 'msg', 'DTrim', and 'ReverseString' the other strings referenced in this rule may be shared with RuralBishop."
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        rev = 3
        author = "FireEye"
    strings:
        $msg = "msg" ascii wide
        $msil = "_CorExeMain" ascii wide
        $str1 = "RuralBishop" ascii wide
        $str2 = "KnightKingside" ascii wide
        $str3 = "ReadShellcode" ascii wide
        $str4 = "ReverseString" ascii wide
        $str5 = "DTrim" ascii wide
        $str6 = "QueensGambit" ascii wide
        $str7 = "Messages" ascii wide
        $str8 = "NtQueueApcThread" ascii wide
        $str9 = "NtAlertResumeThread" ascii wide
        $str10 = "NtQueryInformationThread" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and #msg > 60 and all of ($str*)
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_WildChild_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the WildChild project."
        md5 = "7e6bc0ed11c2532b2ae7060327457812"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid1 = "2e71d5ff-ece4-4006-9e98-37bb724a7780" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_WMIRunner_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIRunner' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "6cc61995-9fd5-4649-b3cc-6f001d60ceda" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_Win_Generic_17
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "562ecbba043552d59a0f23f61cea0983"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_Win_Generic_18
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "c74ebb6c238bbfaefd5b32d2bf7c7fcc"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_Win_Generic_19
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "3fb9341fb11eca439b50121c6f7c59c7"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_Win_Generic_20
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "5125979110847d35a338caac6bff2aa8"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Methodology_OLE_CHARENCODING_2
{
    meta:
        description = "Looking for suspicious char encoding"
        md5 = "41b70737fa8dda75d5e95c82699c2e9b"
        rev = 4
        author = "FireEye"
    strings:
        $echo1 = "101;99;104;111;32;111;102;102;" ascii wide
        $echo2 = "101:99:104:111:32:111:102:102:" ascii wide
        $echo3 = "101x99x104x111x32x111x102x102x" ascii wide
        $pe1 = "77;90;144;" ascii wide
        $pe2 = "77:90:144:" ascii wide
        $pe3 = "77x90x144x" ascii wide
        $pk1 = "80;75;3;4;" ascii wide
        $pk2 = "80:75:3:4:" ascii wide
        $pk3 = "80x75x3x4x" ascii wide
    condition:
        (uint32(0) == 0xe011cfd0) and filesize < 10MB and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule MSIL_Launcher_DUEDLLIGENCE_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
        md5 = "a91bf61cc18705be2288a0f6f125068f"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "73948912-cebd-48ed-85e2-85fcd1d4f560" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Tool_MSIL_CSharpUtils_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CSharpUtils' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "2130bcd9-7dd8-4565-8414-323ec533448d" ascii nocase wide
        $typelibguid1 = "319228f0-2c55-4ce1-ae87-9e21d7db1e40" ascii nocase wide
        $typelibguid2 = "4471fef9-84f5-4ddd-bc0c-31f2f3e0db9e" ascii nocase wide
        $typelibguid3 = "5c3bf9db-1167-4ef7-b04c-1d90a094f5c3" ascii nocase wide
        $typelibguid4 = "ea383a0f-81d5-4fa8-8c57-a950da17e031" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Tool_MSIL_SharpGrep_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGrep' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "f65d75b5-a2a6-488f-b745-e67fc075f445" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_Macro_RESUMEPLEASE_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "d5d3d23c8573d999f1c48d3e211b1066"
        rev = 1
        author = "FireEye"
    strings:
        $str00 = "For Binary As"
        $str01 = "Range.Text"
        $str02 = "Environ("
        $str03 = "CByte("
        $str04 = ".SpawnInstance_"
        $str05 = ".Create("
    condition:
        all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_MSIL_GORAT_Module_PowerShell_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
        $typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_MSIL_GORAT_Plugin_DOTNET_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Plugin - .NET' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "cd9407d0-fc8d-41ed-832d-da94daa3e064" ascii nocase wide
        $typelibguid1 = "fc3daedf-1d01-4490-8032-b978079d8c2d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_Raw_Generic_4
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "f41074be5b423afb02a74bc74222e35d"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_Win64_Generic_22
{
    meta:
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        rev = 2
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
        $process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
        $token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_Win64_Generic_23
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "b66347ef110e60b064474ae746701d4a"
        rev = 1
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { 8B 85 [4] C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 44 8B C0 33 D2 48 8B 8D [4] FF 15 [4] 48 89 45 ?? 48 83 7D ?? 00 75 ?? 48 8B 45 ?? E9 [4] 8B 85 [4] 48 C7 44 24 20 00 00 00 00 44 8B C8 4C 8B 85 [4] 48 8B 55 ?? 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? 48 8B 45 ?? EB ?? 8B 85 [4] 48 8B 4D ?? 48 03 C8 48 8B C1 48 89 45 48 48 8D 85 [4] 48 89 44 24 30 C7 44 24 28 00 00 00 00 48 8B 85 [4] 48 89 44 24 20 4C 8B 4D ?? 41 B8 00 00 10 00 33 D2 48 8B 8D [4] FF 15 }
        $process = { 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 08 00 00 00 4C 8D 8D [4] 41 B8 00 00 02 00 33 D2 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? E9 [4] 48 8B 85 [4] 48 89 85 [4] 48 8D 85 [4] 48 89 44 24 50 48 8D 85 [4] 48 89 44 24 48 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 C7 44 24 30 04 00 08 00 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 [4] 33 D2 48 8B [2-5] FF 15 }
        $token = { FF 15 [4] 4C 8D 45 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 75 ?? E9 [4] 48 8D [2-5] 48 89 44 24 28 C7 44 24 20 02 00 00 00 41 B9 02 00 00 00 45 33 C0 BA 0B 00 00 00 48 8B 4D ?? FF 15 [4] 85 C0 75 ?? E9 [4] 4C 8D 8D [4] 45 33 C0 BA 01 00 00 00 33 C9 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_Win_Generic_101
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "2e67c62bd0307c04af469ee8dcb220f2"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
        $s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
        $s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
        $si1 = "PeekMessageA" fullword
        $si2 = "PostThreadMessageA" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and @s0[1] < @s1[1] and @s1[1] < @s2[1] and all of them
}rule aPLib_decompression
{     
	meta:
		description = "Detects aPLib decompression code often used in malware"
		author="@r3c0nst"
		date="2021-24-03"
		reference="https://ibsensoftware.com/files/aPLib-1.1.1.zip"

	strings:
		$pattern1 = { FC B2 80 31 DB A4 B3 02 }
		$pattern2 = { AC D1 E8 74 ?? 11 C9 EB }
		$pattern3 = { 73 0A 80 FC 05 73 ?? 83 F8 7F 77 }

	condition:
		filesize < 10MB and all of them
}
rule Gamaredon_GetImportByHash {
  meta:
	description = "Detects Gamaredon APIHashing"
        author = "Frank Boldewin (@r3c0nst)"
        date = "2021-05-12"
	hash1 = "2d03a301bae0e95a355acd464afc77fde88dd00232aad6c8580b365f97f67a79"
	hash2 = "43d6e56515cca476f7279c3f276bf848da4bc13fd15fad9663b9e044970253e8"
	hash3 = "5c09f6ebb7243994ddc466058d5dc9920a5fced5e843200b1f057bda087b8ba6"
    
  strings:
	$ParseImgExportDir = { 8B 50 3C 03 D0 8B 52 78 03 D0 8B 4A 1C 03 C8 }
	$djb2Hashing = { 8B 75 08 BA 05 15 00 00 8B C2 C1 E2 05 03 D0 33 DB 8A 1E 03 D3 46 33 DB 8A 1E 85 DB 75 } // https://theartincode.stanis.me/008-djb2/
	
  condition:
	uint16(0) == 0x5a4d and all of them
}
rule ATM_Malware_JavaDispCash {
	meta:
		description = "Detects ATM Malware JavaDispCash"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1111254169623674882"
		date = "2019-03-28"
		hash1 = "0149667c0f8cbfc216ef9d1f3154643cbbf6940e6f24a09c92a82dd7370a5027"
		hash2 = "ef407db8c79033027858364fd7a04eeb70cf37b7c3a10069a92bae96da88dfaa"
		
	strings:
		$CashInfo = "getNumberOfCashUnits" nocase ascii wide
		$Dispense = "waitforbillstaken" nocase ascii wide
		$Inject = "No code to inject!" nocase ascii wide
		$config = ".Agentcli" nocase ascii wide
		$log1 = "logft.log" nocase ascii wide
		$log2 = ".loginside" nocase ascii wide
		
	condition:
		uint16(0) == 0x4B50 and filesize < 500KB and all of them
}
rule ATM_Malware_XFS_ALICE {
	meta:
		description = "Detects ATM Malware ALICE"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1215265889844637696"
		date = "2020-01-09"
		hash1 = "6b2fac8331e4b3e108aa829b297347f686ade233b24d94d881dc4eff81b9eb30"
		
	strings:
		$String1 = "Project Alice" ascii nocase
		$String2 = "Can't dispense requested amount." ascii nocase
		$String3 = "Selected cassette is unavailable" ascii nocase
		$String4 = "ATM update manager" wide nocase
		$String5 = "Input PIN-code for access" wide nocase
		$String6 = "Supervisor ID" wide nocase
		$Code1 = {50 68 08 07 00 00 6A 00 FF 75 0C FF 75 08 E8} // Get Cash Unit Info
		$Code2 = {50 6A 00 FF 75 10 FF 75 0C FF 75 08 E8} // Dispense Cash
		$Code3 = {68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 0B C0 75 29 6A} // Check Supervisor ID
		
	condition:
		uint16(0) == 0x5A4D and filesize < 200KB and 4 of ($String*) and all of ($Code*)
}
import "pe"

rule ATM_Malware_ATMITCH {
	meta:
		description = "Detects ATM Malware ATMItch"
		author = "Frank Boldewin (@r3c0nst)"
	strings:
		$STRING1 = "SCREEN and think what does you DO" nocase ascii wide
		$STRING2 = "Receive CASH UNIT info first, then LOOK on" nocase ascii wide
		$STRING3 = "Unknown command mnemonic, check it and repeat again" nocase ascii wide
		$STRING4 = "Catch some money, bitch!" nocase ascii wide
	condition:
		(uint16(0) == 0x5A4D and 1 of them) or (pe.imphash() == "655ad5439db0832c5a3f86d0a68ddaac")
}
import "hash"	

rule ATM_Malware_ATMSpitter {
  meta:
		description = "Detects ATM Malware ATMSpitter"
		author = "Frank Boldewin (@r3c0nst)"
		reference1 = "https://www.straitstimes.com/asia/east-asia/thieves-steal-3-million-in-taiwan-atm-heist-with-help-of-malware"
		reference2 = "https://topics.amcham.com.tw/2017/02/looking-back-at-the-first-banks-atm-heist/"
		date = "2016-07-20"
		hash = "658b0502b53f718bd0611a638dfd5969"
	
	strings:
		$Code_Bytes =  { B9 E0 07 00 00 66 ?? ?? ?? ?? 0F 85 DD 02 00 00 66 ?? ?? ?? ?? ?? 0F 85 D1 02 00 00 }
		
		$Service = "Congratulations! You are very skilled in reverse engineering!" nocase ascii
	
	condition:
		(hash.sha256(0, filesize) == "4035d977202b44666885f9781ac8755c799350a03838ff782eb730c0d7069958")
		or ($Code_Bytes and $Service)
		
}
rule ATM_Malware_DispCashBR {
	meta:
		description = "Detects ATM Malware DispCashBR"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1232944566208286720"
		date = "2020-02-27"
		hash1 = "7cea6510434f2c8f28c9dbada7973449bb1f844cfe589cdc103c9946c2673036"
		
	strings:
		$String1 = "(*) Dispensando: %lu" ascii nocase
		$String2 = "COMANDO EXECUTADO COM SUCESSO" ascii nocase
		$String3 = "[+] FOI SACADO:  %lu R$ [+]" ascii nocase
		$DbgStr1 = "_Get_Information_cdm_cuinfo" ascii nocase
		$DbgStr2 = "_GET_INFORMATION_SHUTTER" ascii nocase
		$Code1 = {C7 44 24 08 00 00 00 00 C7 44 24 04 2F 01 00 00 89 04 24 E8} // CDM Info1
		$Code2 = {C7 44 24 08 00 00 00 00 C7 44 24 04 17 05 00 00 89 04 24 E8} // CDM Info2
		$Code3 = {89 4C 24 08 C7 44 24 04 2E 01 00 00 89 04 24 E8} // Dispense Cash
		
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and 2 of ($String*) and 1 of ($DbgStr*) and all of ($Code*)
}
import "hash"

rule ATM_Malware_DispenserXFS {

	strings:
		$Code_Bytes =  { 68 FF FF 00 00 68 60 EA 00 00 6A 10 }
		
		$XFSKILL = "injected mxsfs killer into" nocase ascii wide
		$PDB       = "C:\\_bkittest\\dispenser\\Release_noToken\\dispenserXFS.pdb" nocase ascii wide
	condition:
		(hash.sha256(0, filesize) == "867991ade335186baa19a227e3a044c8321a6cef96c23c98eef21fe6b87edf6a")
		or (uint16(0) == 0x5A4D and 1 of them)
}
rule ATM_Malware_Loup {
	meta:
		description = "Detects ATM Malware Loup"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1295275546780327936"
		date = "2020-08-17"
		hash = "6c9e9f78963ab3e7acb43826906af22571250dc025f9e7116e0201b805dc1196"
		
	strings:
		$String1 = "C:\\Users\\muham\\source\\repos\\loup\\Debug\\loup.pdb" ascii nocase
		$String2 = "CurrencyDispenser1" ascii nocase
		$Code = {50 68 C0 D4 01 00 8D 4D E8 51 68 2E 01 00 00 0F B7 55 08 52 E8} // Dispense
		
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and all of ($String*) and $Code
}
import "hash"

rule ATM_Malware_NVISOSPIT {
	meta:
		description = "Detects ATM Malware NVISOSPIT"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1134403094157115392"
		date = "2019-05-31"
		hash = "d7ce7b152f0da49e96fa32a9336b35253905d9940b001288d0df55d8f8b3951f"
		
	strings:
		$MalwareName = "NVISOSPIT" ascii fullword
		$DispenseCommand = "Calling WFSExecute() to dispense $%d" fullword ascii
		// CurrencyID --> Kyat MMK (Currency in Myanmar)
		$Code = {C6 85 7D F9 FF FF 4D C6 85 7E F9 FF FF 4D C6 85 7F F9 FF FF 4B}
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and 2 of them
}
import "pe"

rule ATM_Malware_PloutusI {
	meta:
		description = "Detects Ploutus I .NET samples based on MetabaseQ report"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/ATM.Malware.PloutusI.yar"
		date = "2021-03-03"
		hash1 = "4f6d4c6f97caf888a98a3097b663055b63e605f15ea8f7cc7347283a0b8424c1"
		hash2 = "8ca29597152dc79bcf79394e1ae2635b393d844bb0eeef6709d37e6778457b31"
		hash3 = "dce1f01c08937fb5c98964a0911de403eed2101a9d46c5eb9899755c40c3765a"
		hash4 = "3a1d992277a862640a0835af9dff4b029cfc6c5451e9716f106efaf07702a98c"
		description = "https://www.metabaseq.com/recursos/ploutus-is-back-targeting-itautec-atms-in-latin-america"
		
	strings:
		$Code = {28 ?? 02 00 06 2a}

	condition:
		filesize < 300KB and
		$Code and
		pe.pdb_path contains "Diebold.pdb" and
		pe.imports("mscoree.dll", "_CorExeMain") and
		(for any i in (0..pe.number_of_resources -1): (
			pe.resources[i].type == pe.RESOURCE_TYPE_VERSION and
			(pe.version_info["InternalName"] contains "Diebold.exe")))
}
rule ATM_Malware_Ripper : ATMRIPPER malware
{
    meta:
        description = "Rule detects Thailand ATM Jackpot malware RIPPER (unpacked)"
        last_modified = "2016-08-01"
        malware_family = "ATM-malware RIPPER"
	author = "Frank Boldewin"
	
    strings:
        $Card_Hash1 = "be59a724feae790b3f315edf71a8450888c021f113e3c2b471e174130c201852" nocase ascii
	$Card_Hash2 = "f26a57da928d6f3e3480dfc7d03761161191bdb170e10ca15c7ac5de6912945c" nocase ascii
	$Card_Hash3 = "692cdaf6e42ab3a4f307e5d047249f7b30ceddd6bc88f22ca032412419bd62b7" nocase ascii
	$Card_Hash4 = "0679c7c0c9b0d6919c12cbc087e942d7bf48d3a78cd3ec80321fbfd1b33a1904" nocase ascii
		
	$Code_Bytes1 =  { 68 CB 00 00 00 50 FF 15 ?? ?? ?? ?? EB 19 }
	$Code_Bytes2 =  { E8 ?? ?? ?? ?? 83 C4 18 6A 02 53 53 FF 15 ?? ?? ?? ?? 68 74 12 43 00 8D 55 A4 }
	
	$Service = "DBACKUP SERVICE" nocase wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 2 of ($Card_Hash*) and all of ($Code_Bytes*) and filesize < 400KB and ($Service in (0x2f000..0x30000))
}
rule ATM_Malware_XFSADM {
	meta:
		description = "Detects ATM Malware XFSADM"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1149043362244308992"
		date = "2019-06-21"
		hash1 = "2740bd2b7aa0eaa8de2135dd710eb669d4c4c91d29eefbf54f1b81165ad2da4d"

	strings:
		$Code1 = {68 88 13 00 00 FF 35 ?? ?? ?? ?? 68 CF 00 00 00 50 FF 15} // Read Card Data
		$Code2 = {68 98 01 00 00 50 FF 15} // Get PIN Data
		$Mutex = "myXFSADM" nocase wide
		$MSXFSDIR = "C:\\Windows\\System32\\msxfs.dll" nocase ascii
		$XFSCommand1 = "WfsExecute" nocase ascii
		$XFSCommand2 = "WfsGetInfo" nocase ascii
		$PDB = "C:\\Work64\\ADM\\XFS\\Release\\XFS.pdb" nocase ascii
		$WindowName = "XFS ADM" nocase wide
		$FindWindow = "ADM rec" nocase wide
		$LogFile = "xfs.log" nocase ascii
		$TmpFile = "~pipe.tmp" nocase ascii
		
	condition:
		uint16(0) == 0x5A4D and filesize < 500KB and 4 of them
}
rule ATM_Malware_XFSCashNCR {
	meta:
		description = "Detects ATM Malware XFSCashNCR"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1166773324548063232"
		date = "2019-08-28"
		hash1 = "d6dff67a6b4423b5721908bdcc668951f33b3c214e318051c96e8c158e8931c0"

	strings:
		$Code1 = {50 8b 4d e8 8b 51 10 52 6a 00 68 2d 01 00 00 8b 45 e8 0f b7 48 1c 51 e8} // CDM Status
		$Code2 = {52 8d 45 d0 50 68 2e 01 00 00 8b 4d e8 0f b7 51 1c 52 e8} // Dispense
		$StatusMessage1 = "[+] Ingrese Denominacion ISO" nocase ascii
		$StatusMessage2 = "[+] Ingrese numero de billetes" nocase ascii 
		$StatusMessage3 = "[!] FAIL.. dispensadores no encontrados" nocase ascii
		$StatusMessage4 = "[!] Unable continue, IMPOSIBLE abrir dispenser" nocase ascii
		$PDB = "C:\\Users\\cyttek\\Downloads\\xfs_cashXP\\Debug\\xfs_cash_ncr.pdb" nocase ascii
		$LogFile = "XfsLog.txt" nocase ascii
		
	condition:
		uint16(0) == 0x5A4D and filesize < 1500KB and 4 of them
}
rule ATM_Malware_XFS_DIRECT {
	meta:
		description = "Detects ATM Malware XFS_DIRECT"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1185237040583106560"
		date = "2019-10-18"
		// Encrypted Layer Hashes (SHA256)
		hash1 = "3e023949fecd5d06b3dff9e86e6fcac6a9ec6c805b93118db43fb4e84fe43ee0"
		hash2 = "303f2a19b286ca5887df2a334f22b5690dda9f092e677786e2a8879044d8ad11"
		hash3 = "15d50938e51ee414124314095d3a27aa477f40413f83d6a2b2a2007efc5a623a"
		hash4 = "0f9cb4dc1ac2777be30145c3271c95a027758203d0de245ec390037f7325d79d"
		hash5 = "141ae291ddae60fd1b232f543bc9b40f3a083521cd7330c427bb8fc5cdd23966"	
		// Fully Unpacked Hashes (SHA256)
		hash6 = "66eb1a8134576db05382109eec7e297149f25a021aba5171d2f99aa49c381456"
		hash7 = "ac20b12beefb2036595780aaf7ec29203e2e09b6237d93cd26eaa811cebd6665"
		hash8 = "901fc474f50eb62edc526593208a7eec4df694e342ffc5b895d1dcec953c6899"
		hash9 = "56548c26741b25b15c27a0de498c5e04c69b0c9250ba35e3a578bc2f05eedd07"
		hash10 = "c89f1d562983398ab2d6dd75e4e30cc0e95eab57cdf48c4a17619dca9ecc0748"
		
	strings:
		// with encryption layer
		$EncLayer1 = {0F B6 51 FC 30 50 FF 0F B6 11 30 10 0F B6 51 04 30 50 01 0F B6 51 08 30 50 02}
		$EncLayer2 = {B8 4D 5A 00 00 89 33 66 39 06 75 ?? 8b ?? 3c}
		// fully unpacked
		$String1 = "NOW ENTER MASTER KEY" ascii  nocase
		$String2 = "Closing app, than delete myself." ascii nocase
		$String3 = "Number of phisical cash units is:" ascii nocase
		$String4 = "COULD NOT ENABLE or DISABLE connection" ascii nocase
		$String5 = "XFS_DIRECT" ascii nocase
		$String6 = "Take the money you snicky mother fucker :)" ascii  nocase
		$String7 = "ATM IS TEMPORARILY OUT OF SERVICE!" wide nocase
		$Code1 = {D1 F8 89 44 24 10 DB 44 24 10 DC 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 35 2F 81 0B 00 A3} // Session Key Code
		$Code2 = {8B ?? ?? ?? 68 2E 01 00 00 52 C7 ?? 06 01 00 00 00} // Dispense Code
		
	condition:
		uint16(0) == 0x5A4D and (filesize < 1500KB and all of ($EncLayer*)) or (filesize < 300KB and 4 of ($String*) and all of ($Code*))
}
import "pe"

rule ATM_CINEO4060_Blackbox {
    meta:
        description = "Detects Malware samples for Diebold Nixdorf CINEO 4060 ATMs used in blackboxing attacks across Europe since May 2021"
        author = "Frank Boldewin (@r3c0nst)"
        date = "2021-05-25"
	references = "https://twitter.com/r3c0nst/status/1539036442516660224"

    strings:
        $MyAgent1 = "javaagentsdemo/ClassListingTransformer.class" ascii fullword
        $MyAgent2 = "javaagentsdemo/MyUtils.class" ascii fullword
	$MyAgent3 = "javaagentsdemo/SimplestAgent.class" ascii fullword
	$Hook = "### [HookAPI]: Switching context!" fullword ascii
	$Delphi = "Borland\\Delphi\\RTL" fullword ascii

	$WMIHOOK1 = "TPM_SK.DLL" fullword ascii
	$WMIHOOK2 = "GetPCData" fullword ascii
	$WMIHOOK3 = {60 9C A3 E4 2B 41 00 E8 ?? ?? ?? ?? 9D 61 B8 02 00 00 00 C3} //Hook function
	$TRICK1 = "USERAUTH.DLL"  fullword ascii
	$TRICK2 = "GetAllSticksByID"  fullword ascii
	$TRICK3 = {6A 06 8B 45 FC 8B 00 B1 4F BA 1C 00 00 00}  //Hook function

    condition:
        (uint16(0) == 0x4b50 and filesize < 50KB and all of ($MyAgent*)) or
	(uint16(0) == 0x5A4D and (pe.characteristics & pe.DLL) and $Hook and $Delphi and all of ($WMIHOOK*) or all of ($TRICK*))
}
rule Exploit_Outlook_CVE_2023_23397 {
	meta:
		Description = "Detects Outlook appointments exploiting CVE-2023-23397"
		Reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		Author = "Frank Boldewin (@r3c0nst)"
		Date = "2023-03-19"
		Hash1 = "078b5023cae7bd784a84ec4ee8df305ee7825025265bf2ddc1f5238c3e432f5f"
		Hash2 = "a034427fd8524fd62380c881c30b9ab483535974ddd567556692cffc206809d1"
		Hash3 = "e7a1391dd53f349094c1235760ed0642519fd87baf740839817d47488b9aef02"
		Hash4 = "1543677037fa339877e1d6ef2d077f94613afbcd6434d7181a18df74aca7742b"
		
	strings:
		$ipmtask = "IPM.Task" wide ascii
		$ipmappointment = "IPM.Appointment" wide ascii
		$ipmtaskb64 = "IPM.Task" base64 base64wide
		$ipmappointmentb64 = "IPM.Appointment" base64 base64wide
		// CVE-2023_23397 exploits the PidLidReminderFileParameter property, which usally is being used to play an appointment reminder sound.
		// Malicious calendar appointments use attacker controlled UNC paths to trigger a forced NTLM authentication to harvest user hashes.
		$unc_path1 = { 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00|3? 00 3? 00|3? 00 3? 00 3? 00) }
		$unc_path2 = { 5C 5C (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3?|3? 3?|3? 3? 3?) }
		$unc_a = "\x00\x00\x00\x5c\x5c" base64
		$unc_w = "\x00\x00\x5c\x00\x5c" base64wide
		$mail1 = "from:" ascii wide nocase
		$mail2 = "received:" ascii wide nocase

	condition:
		((uint32be(0) == 0xD0CF11E0 or uint32be(0) == 0x789F3E22) or (all of ($mail*))) and
		(($ipmtask or $ipmappointment) or ($ipmtaskb64 or $ipmappointmentb64)) and
		(($unc_path1 or $unc_path2) or ($unc_a or $unc_w))
}
rule Stealbit {
	meta:
		description = "Detects Stealbit used by Lockbit 2.0 Ransomware Gang"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Lockbit2.Stealbit.yar"
		date = "2021-08-12"
		hash1 = "3407f26b3d69f1dfce76782fee1256274cf92f744c65aa1ff2d3eaaaf61b0b1d"
		hash2 = "bd14872dd9fdead89fc074fdc5832caea4ceac02983ec41f814278130b3f943e"
		
	strings:
		$C2Decryption = {33 C9 8B C1 83 E0 0F 8A 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 F9 7C 72 E9 E8}
		
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and $C2Decryption
}
import "pe"

rule Nighthawk_RAT
{
	meta:
		description = "Detects Nighthawk RAT"
		author = "Frank Boldewin (@r3c0nst)"
		references = "https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		hash1 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"
		hash2 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		hash3 = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
		hash4 = "f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e"
		hash5 = "b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94"
		date = "2022-30-11"

	strings:
		$pattern1 = { 48 8d 0d ?? ?? ?? ?? 51 5a 48 81 c1 ?? ?? ?? ?? 48 81 c2 ?? ?? ?? ?? ff e2 }
		$pattern2 = { 66 03 D2 66 33 D1 66 C1 E2 02 66 33 D1 66 23 D0 0F B7 C1 }
		$pattern3 = { FF 7F 48 3B F0 48 0F 47 F0 48 8D }
		$pattern4 = { 65 48 8B 04 25 30 00 00 00 8B 40 68 49 89 CA 0F 05 C3 }
		$pattern5 = { 48 B8 AA AA AA AA AA AA AA 02 48 ?? ?? ?? ?? 0F 84 }
		$pattern6 = { 65 48 8B 04 25 30 00 00 00 48 8B 80 }

	condition:
		uint16(0) == 0x5A4D and filesize < 2MB and
		(3 of ($pattern*) or
		(pe.section_index(".profile") and pe.section_index(".detourc") and pe.section_index(".detourd")))
}
rule Prolock_Malware {
	meta:
		description = "Detects Prolock malware in encrypted and decrypted mode"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Prolock.Malware.yar"
		date = "2020-05-17"
		hash1 = "a6ded68af5a6e5cc8c1adee029347ec72da3b10a439d98f79f4b15801abd7af0"
		hash2 = "dfbd62a3d1b239601e17a5533e5cef53036647901f3fb72be76d92063e279178"
		
	strings:
		$DecryptionRoutine1 = {31 04 1A 81 3C 1A 90 90 90 90 74}
		$DecryptionRoutine2 = {83 C3 04 81 3C 1A C4 C4 C4 C4 74}
		$DecryptedString1 = "support981723721@protonmail.com" nocase ascii
		$DecryptedString2 = "Your files have been encrypted by ProLock Ransomware" nocase ascii
		$DecryptedString3 = "msaoyrayohnp32tcgwcanhjouetb5k54aekgnwg7dcvtgtecpumrxpqd.onion" nocase ascii
		$CryptoCode = {B8 63 51 E1 B7 31 D2 8D BE ?? ?? ?? ?? B9 63 51 E1 B7 81 C1 B9 79 37 9E}
		
	condition:
		((uint16(0) == 0x5A4D) or (uint16(0) == 0x4D42)) and filesize < 100KB and all of ($DecryptionRoutine*) or (1 of ($DecryptedString*) and $CryptoCode)
}
rule RansomWare_GermanWiper {
	meta:
		description = "Detects RansomWare GermanWiper in Memory or in unpacked state"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1158326526766657538"
		date = "2019-08-05"
		hash_packed = "41364427dee49bf544dcff61a6899b3b7e59852435e4107931e294079a42de7c"
		hash_unpacked = "708967cad421bb2396017bdd10a42e6799da27e29264f4b5fb095c0e3503e447"

	strings:
		$PurgeCode = {6a 00 8b 47 08 50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f0 8b d7 8b c3 e8} // code patterns for process kills
		$Mutex1 = "HSDFSD-HFSD-3241-91E7-ASDGSDGHH" nocase ascii
		$Mutex2 = "cFgxTERNWEVhM2V" nocase ascii
		$ProcessKill1 = "oracle.exe" nocase ascii
		$ProcessKill2 = "sqbcoreservice.exe" nocase ascii
		$ProcessKill3 = "isqlplussvc.exe"  nocase ascii
		$ProcessKill4 = "mysqld.exe" nocase ascii
		$KillShadowCopies = "vssadmin.exe delete shadows" nocase ascii
		$Domain1 = "cdnjs.cloudflare.com" nocase ascii
		$Domain2 = "expandingdelegation.top" nocase ascii
		$RansomNote = "Entschluesselungs_Anleitung.html" nocase ascii
		
	condition:
		uint16(0) == 0x5A4D and filesize < 1000KB and 5 of them
}
rule Shellcode_APIHashing_FIN8 {
	meta:
		description = "Detects FIN8 Shellcode APIHashing"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2021-03-16"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/394/Bitdefender-PR-Whitepaper-BADHATCH-creat5237-en-EN.pdf"

	strings:
		$APIHashing32bit1 = {68 F2 55 03 88 68 65 19 6D 1E} 
		$APIHashing32bit2 = {68 9B 59 27 21 C1 E9 17 33 4C 24 10 68 37 5C 32 F4} 
		
		$APIHashing64bit = {49 BF 65 19 6D 1E F2 55 03 88 49 BE 37 5C 32 F4 9B 59 27 21} 
		
	condition:
		all of ($APIHashing32bit*) or $APIHashing64bit

     /*
	#include <string.h>
	#include <stdio.h>
	#include <stdint.h>
	#include <inttypes.h>
	
	static uint64_t hash_fast64(const void *buf, size_t len, uint64_t seed)
	{
		const uint64_t    m = 0x880355f21e6d1965ULL;
		const uint64_t *pos = (const uint64_t *)buf;
		const uint64_t *end = pos + (len >> 3);
		const unsigned char *pc;
		uint64_t h = len * m ^ seed;
		uint64_t v;
		
		while (pos != end)
		{
			v = *pos++;
			v ^= v >> 23;
			v *= 0x2127599bf4325c37ULL;
			h ^= v ^ (v >> 47);
			h *= m;
		}
		
		pc = (const unsigned char*)pos;
		v = 0;
		
		switch (len & 7) {
			case 7: v ^= (uint64_t)pc[6] << 48;
			case 6: v ^= (uint64_t)pc[5] << 40;
			case 5: v ^= (uint64_t)pc[4] << 32;
			case 4: v ^= (uint64_t)pc[3] << 24;
			case 3: v ^= (uint64_t)pc[2] << 16;
			case 2: v ^= (uint64_t)pc[1] << 8;
			case 1: v ^= (uint64_t)pc[0];
			v ^= v >> 23;
			v *= 0x2127599bf4325c37ULL;
			h ^= v ^ (v >> 47);
			h *= m;
		}

		h ^= h >> 23;
		h *= 0x2127599bf4325c37ULL;
		h ^= h >> 47;
		return h;
	}

	void main (void)
	{
		uint64_t h = 0;
		uint64_t seed = 0x0AB00D73069525D99; // Searching for precalculated hashes is quite useless, as new seeds change results.
		char buf[12] = "VirtualAlloc"; // Sample API Function
	
		h = hash_fast64(buf, 12, seed);
		printf ("Hash: 0x%16llx\n",h);   // Output as expected "Hash: 0xb6233cd91b71af58"
	}
     */
}
rule UNC2891_Caketap
{
	meta:
		description = "Detects UNC2891 Rootkit Caketap"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"		

	strings:
		$str1  = ".caahGss187" ascii fullword // SyS_mkdir hook cmd ident
		$str2 = "ipstat" ascii // rootkit lkm name
		$code1 = {41 80 7E 06 4B 75 ?? 41 80 7E 07 57 75 ?? 41 0F B6 46 2B} // HSM cmd KW check
		$code2 = {41 C6 46 01 3D 41 C6 46 08 32} // mode_flag switch

	condition:
        uint32 (0) ==  0x464c457f and (all of ($code*) or (all of ($str*) and #str2 == 2))
}
rule UNC2891_Slapstick
{
	meta:
		description = "Detects UNC2891 Slapstick pam backdoor"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"		
		hash1 = "9d0165e0484c31bd4ea467650b2ae2f359f67ae1016af49326bb374cead5f789"
		
	strings:
		$code1 = {F6 50 04 48 FF C0 48 39 D0 75 F5} // string decrypter
		$code2 = {88 01 48 FF C1 8A 11 89 C8 29 F8 84 D2 0F 85} // log buf crypter
		$str1 = "/proc/self/exe" fullword ascii
		$str2 = "%-23s %-23s %-23s %-23s %-23s %s" fullword ascii
		$str3 = "pam_sm_authenticate" ascii
		$str4 = "ACCESS GRANTED & WELCOME" xor // pam prompt message

	condition:
		uint32 (0) ==  0x464c457f and filesize < 100KB and (all of ($code*) or all of ($str*))
}
rule UNC2891_Steelcorgi
{
	meta:
		description = "Detects UNC2891 Steelcorgi packed ELF binaries"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"
		hash1 = "0760cd30d18517e87bf9fd8555513423db1cd80730b47f57167219ddbf91f170"
		hash2 = "3560ed07aac67f73ef910d0b928db3c0bb5f106b5daee054666638b6575a89c5"
		hash3 = "5b4bb50055b31dbd897172583c7046dd27cd03e1e3d84f7a23837e8df7943547"
		
	strings:
		$pattern1 = {70 61 64 00 6C 63 6B 00} // padlck
		$pattern2 = {FF 72 FF 6F FF 63 FF 2F FF 73 FF 65 FF 6C FF 66 FF 2F FF 65 FF 78 FF 65} // proc_self_exe
		
	condition:
		uint32(0) == 0x464c457f and all of them
}
rule UNC2891_Winghook
{
	meta:
		description = "Detects UNC2891 Winghook Keylogger"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"		
		hash1 = "d071ee723982cf53e4bce89f3de5a8ef1853457b21bffdae387c4c2bd160a38e"

	strings:
		$code1 = {01 F9 81 E1 FF 00 00 00 41 89 CA [15] 44 01 CF 81 E7 FF 00 00 00} // crypt log file data
		$code2 = {83 E2 0F 0F B6 14 1? 32 14 01 88 14 0? 48 83 ?? ?? 48 83 ?? ?? 75} // decrypt path+logfile name
		$str1 = "fgets" ascii // hook function name
		$str2 = "read" ascii // hook function name

	condition:
		uint32 (0) ==  0x464c457f and filesize < 100KB and 1 of ($code*) and all of ($str*)
}
/* Copyright (c) 2016 Tyler McLellan  TyLabs.com
 * QuickSand.io - Document malware forensics tool
 *
 * File quicksand_exe.yara   Dec 10 2016
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 * Commercial licensing is available for the full version.
 */

rule executable_win_pe {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /MZ.{76}This program /
condition:
            1 of them
}

rule executable_win_pe_transposed {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /ZM.{76}hTsip orrgma/
condition:
            1 of them
}


rule executable_win_pe_transposed_offbyone {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /Z.{76}ih srpgoar macnntob  eur nniD SOm do/
condition:
            1 of them
}



rule executable_win {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = "This program cannot be run in DOS mode"
		$s2 = "This program must be run under Win32"
		$s4 = "LoadLibraryA"
		$s5 = "GetModuleHandleA"
		$s6 = "GetCommandLineA"
		$s7 = "GetSystemMetrics" 
		$s8 = "GetProcAddress"
		$s9 = "CreateProcessA"
		$s10 = "URLDownloadToFileA"
		$s11 = "EnterCriticalSection"
		$s12 = "GetEnvironmentVariableA"
		$s13 = "CloseHandle"
		$s14 = "CreateFileA"
		$s15 = "URLDownloadToFileA"
		$s16 = "Advapi32.dll"
		$s17 = "RegOpenKeyExA"
		$s18 = "RegDeleteKeyA"
		$s19 = "user32.dll"
		$s20 = "shell32.dll"
		$s21 = "KERNEL32"
		$s22 = "ExitProcess"
		$s23 = "GetMessageA"
		$s24 = "CreateWindowExA"
		$s25 = {504500004C010100} // PE header
	condition:
            1 of them and not executable_win_pe
}




rule executable_win_transposed {
	meta:
		is_exe = true
		type = "win-tp"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		desc = "Transposition cipher"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = "hTsip orrgmac naon tebr nui  nOD Somed" //string.transposition cipher of This program cannot be run in DOS mode
	condition:
            1 of them and not executable_win_pe_transposed
}

rule executable_win_rtl {
	meta:
		is_exe = true
		type = "win-rtl"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "Right to Left compression LZNT1"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = {2070726F6772616D002063616E6E6F74200062652072756E2069006E20444F53206D6F} // string.RTL.This program cannot be run in DOS mode
	condition:
            1 of them
}

rule executable_win_reversed {
	meta:
		is_exe = true
		type = "win-reversed"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "EXE is stored backwards"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" // string.reverse This program cannot be run in DOS mode	condition:
	condition:
            1 of them
}



rule executable_vb {
	meta:
		is_exe = true
		revision = "100"
		rank = 10
		type = "vb"
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "impersonationLevel=impersonate"
		$s2 = "On Error Resume Next"
		$s3 = "WScript.CreateObject(\"WScript.Shell\")"
		$s4 = "CreateObject(\"Scripting.FileSystemObject\")"
	condition:
            1 of them
}


rule executable_macosx {
	meta:
		is_exe = true
		type = "macosx"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "<key>RunAtLoad</key>"
		$s2 = "__mh_execute_header"
		$s3 = "/Developer/SDKs/MacOSX10.5.sdk/usr/include/libkern/i386/_OSByteOrder.h"
		$s4 = "__gcc_except_tab__TEXT"
		$s5 = "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"
		$s6 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
		$s7 = "@_getaddrinfo"
		$s8 = "@_pthread_create"
		$s9 = "StartupParameters.plist"
		$s10 = "dyld__mach_header"
		$s11 = "/usr/lib/libSystem"
		$s12 = "/usr/lib/dyld"
		$s13 = "__PAGEZERO"
		$s14 = "/usr/lib/libgcc_s"
	condition:
            1 of them
}


/* Copyright (c) 2016, 2017 Tyler McLellan  TyLabs.com
 * @tylabs
 * QuickSand.io - Document malware forensics tool
 *
 * File quicksand_exploits.yara   Nov 20 2017
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 * Commercial licensing is available for the full version.
 */

rule warning_exec_ocx_object {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "OLE application command"
	strings:
		$s1 = "w:ocx w:data=\"DATA:application/x-oleobject"
	condition:
            1 of them
}




rule warning_scriptbridge {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "ScriptBridge may load remote exploit"
	strings:
		$s1 = "ScriptBridge.ScriptBridge.1"

	condition:
            1 of them
}



rule exploit_cve_2006_2492 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "smarttag overflow CVE-2006-2492"
	strings:
		$s1 = {0600DDC6040011000100D65A12000000000001000000060000000300}
		$s2 = {0600C8BE1B0008000200685B1200}
	condition:
            1 of them
}

rule exploit_cve_2009_3129 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "excel buffer overflow CVE-2009-3129"
	strings:
		$s1 = {4F7269656E746174696F6E??504F33}
	condition:
            1 of them
}


rule warning_embedded_flash {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded Flash data"
	strings:
		$cws = {66556655??????00435753}
		$fws = {66556655??????00465753}
		$zws = {66556655??????005a5753}
		$control = "CONTROL ShockwaveFlash.ShockwaveFlash"
		$jit = {076A69745F656767}
		$generic = "ShockwaveFlash.ShockwaveFlash."
		$genericw = "ShockwaveFlash" wide
		$generich = "53686F636B77617665466C6173682E53686F636B77617665466C6173682E"

	condition:
            1 of them
}



rule exploit_cve_2011_0609 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Flash exploit CVE-2011-0609"
	strings:
		$s1 = {4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134}
		$s2 = {34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235}
		$s3 = {3941303139413031394130313941303139064C6F61646572}

	condition:
            1 of them
}

rule exploit_cve_2011_0611 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Flash exploit CVE-2011-061"
	strings:
		$s1 = {7772697465427974650541727261799817343635373533304143433035303030303738}
		$s2 = {5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348}
		$s3 = {343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431}
		$s4 = {3063306330633063306330633063306306537472696E6706}
		$s5 = {410042004300440045004600470048004900A18E110064656661756C74}
		$s6 = {00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277}
		$s7 = "AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB"
    

	condition:
            1 of them
}
    
    
    
rule exploit_cve_2012_0754 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit malformed mp4 CVE-2012-0754"
    strings:
        $s1 = {537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E}
    condition:
        1 of them
}


rule exploit_cve_2010_3333 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
	release = "lite"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "RTF stack overflow pFragments CVE-2010-3333"
    strings:
        $s1 = /sn .{1,300}?pFragments.{1,700}?sv .{1,200}?[a-zA-Z0-9\*\+]{50}?/
        $s2 = "\\sn\\*\\sn-pFragments"
        $s3 = /pFragments.{1,200}?\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x0D\x0A/
        $s4 = /sn pfragments.{1,30}?11111111/
        $s5 = /sn[\W]{1,20}?pFragments/
        $s6 = "\\sn9pFRagMEnTS"
        $s7 = {5C736E34096D656E7473}
    condition:
        1 of them
}
    
    


    
    
rule warning_rtf_embedded_file {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 2
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_warning"
        desc = "TF embedded file package"
    strings:
        $s1 = /objdata.{1,300}\w*5\w*0\w*6\w*1\w*6\w*3\w*6\w*b\w*6\w*1\w*6\w*7\w*6\w*5\w*0\w*0/
        $s2 = "\\objclass Word.Document"
    condition:
        1 of them
}

    
rule exploit_MS12_060_tomato_garden {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit MSCOMCTL.OCX Toolbar MS12-060 Tomato Garden campaign"
    strings:
        $s1 = "CONTROL MSComctlLib.Toolbar.2"
        $s2 = "Toolbar1, 0, 0, MSComctlLib, Toolbar"
        $s3 = "MSComctlLib.Toolbar.2"
        $s4 = {4D53436F6D63746C4C69622E546F6F6C6261722E32}
    condition:
        1 of them
}

    

rule warning_office_encrypted_doc {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 1
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "office encrypted document"
    strings:
        $s1 = {4D006900630072006F0073006F0066007400200042006100730065002000430072007900700074006F0067007200610070006800690063002000500072006F0076006900640065007200200076}
        $s2 = {45006E006300720079007000740065006400530075006D006D006100720079}
    condition:
        1 of them
}

    
    
    
rule exploit_cve_2012_1535 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit CVE-2012-1535"
    strings:
        $s1 = {4578616D706C650B6372656174654C696E65730968656170537072617908686578546F42696E076D782E636F72650A49466C6578417373657409466F6E7441737365740A666C6173682E74657874}
        $s2 = {454D4245444445445F4346460A666F6E744C6F6F6B75700D456C656D656E74466F726D617408666F6E7453697A650B54657874456C656D656E7407636F6E74656E740E637265617465546578744C696E6508546578744C696E650178017906686569676874086164644368696C6406456E6469616E0D4C4954544C455F454E4449414E06656E6469616E223063306330633063}
    condition:
        1 of them
}


    
    
rule exploit_cve_2013_0634 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit CVE-2013-0634 memory corruption"
    strings:
        $s1 = {8A23ABA78A01908B23EED461D8872396A39A02F48523A1F94AB48323FBE0E303}
    condition:
        1 of them
}
   
rule exploit_cve_2012_5054 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit CVE-2012-5054 Matrix3D"
    strings:
        $s1 = {7772697465446F75626C65084D61747269783344064F626A6563740B666C6173682E6D6564696105536F756E640C666C6173682E73797374656D0C4361706162696C69746965730776657273696F6E0B746F4C6F776572436173651077696E}
    condition:
        1 of them
}
    
    
    

    
    
rule exploit_cve_2012_1856 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit MSCOMCTL.OCX TabStrip CVE-2012-1856"
    strings:
        $s1 = "MSComctlLib.TabStrip"
        $s2 = "4d53436f6d63746c4c69622e546162537472697" nocase
        $s3 = "9665fb1e7c85d111b16a00c0f0283628" nocase
        $s4 = "1EFB6596-857C-11D1-B16A-00C0F0283628" nocase

    condition:
        1 of them
    }
    
    
rule warning_mime_mso_embedded_flash {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 1
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
	release = "lite"
        sigtype = "cryptam_exploit"
        desc = "office embedded Flash in MSO file"
    strings:
        $s1 = "D27CDB6E-AE6D-11CF-96B8-444553540000" nocase
    condition:
        1 of them
}


    
rule exploit_cve_2012_0158 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit MSCOMCTL.OCX RCE CVE-2012-0158"
    strings:
        $s1 = /objdata.{1,100}?53436F6D63746C4C69622E4C/
        $s2 = "ListView2, 1, 1, MSComctlLib, ListView"
        $s3 = "ListView1, 1, 0, MSComctlLib, ListView"
        $s4 = /0000000000000000000000000000000000000000000000.{1,300}?49746D736400000002000000010000000C000000436F626A/
        $s5 = /MSComctlLib.ListViewCtrl.{1,25}?objdata/
        $s6 = "MSComctlLib.ListViewCtrl.2"
        $s7 = {4C00690073007400560069006500770041}
        $s8 = {ECBD010005009017190000000800000049746D736400000002000000010000000C000000436F626A??0000008282000082820000000000000000000000000000????????90}
        //$s9 = {3131313131313131310D0D0D1320434F4E54524F4C204D53436F6D63746C4C69622E4C697374566965774374726C2E32}
        $s10 = "978C9E23-D4B0-11CE-BF2D-00AA003F40D0" nocase
        $s11 = "BDD1F04B-858B-11D1-B16A-00C0F0283628" nocase
        $s12 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase
        $s13 = "996BF5E0-8044-4650-ADEB-0B013914E99C" nocase
        $s14 = "9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E" nocase
        $s15 = "\\7300740056006\\"
        $s16 = "4C69{\\*}7374566"
        $s17 = "4C0069007300740056006900650077004" nocase
        $s18 = "4BF0D1BD8B85D111B16A00C0F0283628" nocase
        $s19 = {4BF0D1BD8B85D111B16A00C0F0283628}
        $s20 = "COMCTL.TreeCtrl.1"
        $s21 = {434F4D43544C2E547265654374726C2E31}
	$s22 = "4D53436F6D63746C4C69622E4C697374566965774374726C2E" nocase
	$s23 = "MSComctlLib.ListViewCtrl.0"
	$s24 = {4D 53 43 6F 6D 63 74 6C 4C 69 62 2E 4C 69 73 74 56 69 65 77 43 74 72 6C 2E 30}
	$s25 = "4D53436F6D63746C4C69622E4C697374566965774374726C2E30" nocase


condition:
        1 of them
}
    
    
    
rule warning_activex_exec {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 8
        revision = "3"
        date = "Oct 11 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015, 2017. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "ActiveX content"
    strings:
        $s1 = "MSComctlLib.TreeCtrl.2"
        $s2 = "4D53436F6D63746C4C69622E547265654374726C2E32" nocase
        $s3 = "B69041C78985D111B16A00AA003F40D0" nocase
    $s4 = {B69041C78985D111B16A00AA003F40D0}
    $s5 = "C74190B6-8589-11D1-B16A-00AA003F40D0" nocase
    $s6 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase
    $s7 = {B69041C78985D111B16A00C0F0283628}
    $s8 = "B69041C78985D111B16A00C0F0283628" nocase
    $s9 = "objclass MSComctlLib.ImageComboCtl.2"
    $s10 = "MSComctlLib.ImageComboCtl.2"
    $s11 = {00 4D 53 43 6F 6D 63 74 6C 4C 69 62 2E 49 6D 61 67
        65 43 6F 6D 62 6F 43 74 6C}
    $s12 = {49006D0061006700650043006F006D0062006F00430074006C002000}
    $s13 = "TreeView1, 0, 0, MSComctlLib, TreeView"
    $s14 = "new ActiveXObject"
    $s15 = "<ax:ocx ax:classid=" ascii nocase

    
    condition:
        1 of them
    }



    rule warning_vb_potential_heapspray {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 2
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
	release = "lite"
        sigtype = "cryptam_exploit"
        desc = "office heap spray"
    strings:
        $s1 = "90909090EB7F414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412490909090"
    condition:
        1 of them
    }
    
    
    rule exploit_cve_2013_3906 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit TIFF CVE-2013-3906"
    strings:
        $s1 = {49492A00C8490000803FE0503824160D0784426150B864361D0F8844625138A4562D178C466351B8E4763D1F90486452392418012794496552B964B65D2F984C665339A4D66D379C4E6753B9E4F67D3FA05068543A25168D47A4526954BA65361D2894D3AA553AA556AD57AC566B55BAE576BD5FB0586C563B2596CD67B25424F68B65B6DD6FB85C6E573BA5D6ED77BC5E6F57BBE5F64751BF6070583C26170D87C4627158BC66371D8FA5DA80190CA6572D97CC667359BC5404803FE0503824160D0784426150B864361D0F88446251}
        $s2 = {49492a000800000002000e010200fc3a0000260000006987040001000000223b00007c5a00000a0a0a0a0a}
        $s3 = /jpegblip.{1,20}?49492a00cf660000ffff/
        
    condition:
        1 of them
}
    
    
    
    rule warning_package_manager_embedded {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 1
        revision = "2"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office package manager may load unsafe content such as shell scripts"
    strings:
        $s1 = "0003000C-0000-0000-c000-000000000046" nocase
        $s2 = "0c00030000000000c000000000000046"
        $s3 = {0c00030000000000c000000000000046}
	$s4 = "20a70df22fc0ce11927b0800095ae340" nocase
	$s5 = {20a70df22fc0ce11927b0800095ae340}
        $s7 = "Packager Shell Object" ascii wide
        
    condition:
        1 of them
    }
    

    rule exploit_eicar_test_file {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "eicar test signature"
    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        
    condition:
        $s1
    }




rule warning_vb_macro {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "2"
		date = "Oct 5 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic macro"
	strings:
		$s1 = "Name=\"VBAProject\"" nocase
		$s2 = "OLE Automation" wide nocase
		$s3 = "Visual Basic For Applications" wide nocase
		$s5 = "VBA6\\VBE6.DLL" wide nocase
		$s6 = "000204EF-0000-0000-C000-000000000046" ascii wide
		$s7 = "00020430-0000-0000-C000-000000000046" ascii wide
		$s8 = {000204EF00000000C000000000000046}
		$s9 = {0002043000000000C000000000000046}
		$s10 = "000204EF00000000C000000000000046"
		$s11 = "0002043000000000C000000000000046"
		$s12 = "wne:vbaSuppData" nocase
		$s13 = "wne:macroName" nocase

	condition:
            1 of them
}

rule warning_js_embed {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Apr 12 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
		$s1 = {6a 73 00}
		$s2 = "Package"
		$s3 = {2e 00 6a 00 73}
		$s4 = "Ole10Native" wide
	condition:
            3 of them
}


rule exploit_activex_execute_shell {
	meta:
		is_exploit = true
		is_warning = true
		is_feature = true
		rank = 3
		revision = "2"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic execute shell"
	strings:
		$s1 = "Wscript.Shell" nocase
		$s2 = "netsh firewall set opmode mode=disable" nocase
		$s3 = "Shell" nocase
		$s4 = "CreateObject" nocase
		$s5 = "GetObject" nocase
		$s6 = "SendKeys" nocase
		$s7 = "MacScript" nocase
		$s8 = "FollowHyperlink" nocase
		$s9 = "CreateThread" nocase
		$s10 = "ShellExecute" nocase
		$s11 = "shell.application" nocase
	condition:
            (warning_vb_macro or warning_js_embed) and 1 of them
}




rule warning_vb_autoopen {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Oct 5 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic macro"
	strings:
		$s1 = "Document_Open"
		$s2 = "AutoOpen"
		$s3 = "Document_Close"
		$s4 = "AutoExec"
		$s5 = "Auto_Open"
		$s6 = "AutoClose"
		$s7 = "Auto_Close"
		$s8 = "DocumentBeforeClose"
		$s9 = "DocumentChange"
		$s10 = "Document_New"
		$s11 = "NewDocument"
		$s12 = "Workbook_Open"
		$s13 = "Workbook_Close"

	condition:
            warning_vb_macro and 1 of them
}


rule warning_vb_fileio {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 4
		revision = "2"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic file io"
	strings:
		$s1 = "Scripting.FileSystemObject" nocase
		$s2 = "OpenTextFile"
		$s3 = "FileCopy"
		$s4 = "CopyFile"
		$s5 = "Kill"
		$s6 = "CreateTextFile"
		$s7 = "VirtualAlloc"
		$s8 = "RtlMoveMemory"
		$s9 = "URLDownloadToFileA"
		$s10 = "AltStartupPath"
		$s11 = "URLDownloadToFileA"
		$s12 = "ADODB.Stream"
		$s13 = "WriteText"
		$s14 = "SaveToFile"
		$s15 = "SaveAs"
		$s16 = "SaveAsRTF"
		$s17 = "FileSaveAs"
		$s18 = "MkDir"
		$s19 = "RmDir"
		$s20 = "SaveSetting"
		$s21 = "SetAttr"
	condition:
            warning_vb_macro and 1 of them
}


rule warning_ole2link_embedded {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 1
        revision = "3"
        date = "September 12 2017"
        author = "David Cannings"
        copyright = "source https://github.com/nccgroup/Cyber-Defence/blob/master/Technical%20Notes/Office%20zero-day%20(April%202017)/2017-04%20Office%20OLE2Link%20zero-day%20v0.4.md"
        tlp = "white"
        sigtype = "cryptam_warning"
        desc = "Office OLE2Link unsafe content such as remote risky content"
    strings:
        // Parsers will open files without the full 'rtf'
        $header_rtf = "{\\rt" nocase
        $header_office = { D0 CF 11 E0 }
        $header_xml = "<?xml version=" nocase wide ascii

        // Marks of embedded data (reduce FPs)
        // RTF format
        $embedded_object   = "\\object" nocase
        $embedded_objdata  = "\\objdata" nocase
        $embedded_ocx      = "\\objocx" nocase
        $embedded_objclass = "\\objclass" nocase
        $embedded_oleclass = "\\oleclsid" nocase
    
        // XML Office documents
        $embedded_axocx      = "<ax:ocx"  nocase wide ascii
        $embedded_axclassid  = "ax:classid"  nocase wide ascii

        // OLE format
        $embedded_root_entry = "Root Entry" wide
        $embedded_comp_obj   = "Comp Obj" wide
        $embedded_obj_info   = "Obj Info" wide
        $embedded_ole10      = "Ole10Native" wide

        $data0 = "00000300-0000-0000-C000-000000000046" nocase wide ascii
        $data1 = { 0003000000000000C000000000000046 }
        $data2 = "OLE2Link" nocase wide ascii
        $data3 = "4f4c45324c696e6b" nocase wide ascii
        $data4 = "StdOleLink" nocase wide ascii
        $data5 = "5374644f6c654c696e6b" nocase wide ascii

      condition:
        // Mandatory header plus sign of embedding, then any of the others
        1 of ($header*) and 1 of ($embedded*) 
            and (1 of ($data*))
    }

rule warning_EPS_xor_exec {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 5
        revision = "1"
        date = "May 11 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
        tlp = "green"
        sigtype = "cryptam_exploit"
        desc = "EPS obfuscation using xor and exec"
    strings:
	$h1 = "%!PS-Adobe-" nocase
        $s1 = "mod get xor put"
	$s2 = "exec quit"

    condition:
	$h1 at 0 and all of ($s*)
    }


rule warning_vbs_embed {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "May 18 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded vbs"
	strings:
		$s1 = {2e 76 62 73 00}
		$s2 = "Package"
		$s3 = {2e 00 76 00 62 00 73}
		$s4 = "Ole10Native" wide
	condition:
            3 of them
}

rule exploit_cve_2017_8759 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "September 12 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
        tlp = "green"
        sigtype = "cryptam_exploit"
        desc = "OLE WSDL Parser Code Injection in PrintClientProxy CVE-2017-8759"
	
    strings:
        $c5 = "wsdl=" ascii wide nocase
        $c7 = "wsdl=http" ascii wide nocase
	$c1 = "ECABB0C7-7F19-11D2-978E-0000F8757E2A"
	$c2 = "SoapMoniker"
	$c3 = "c7b0abec-197f-d211-978e-0000f8757e2a"
	$c4 = "c7b0abec197fd211978e0000f8757e2a"
	$c6 = {c7b0abec197fd211978e0000f8757e2a}
        
    condition:
        warning_ole2link_embedded and 1 of ($c*)
}

rule warning_js_inzip {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Oct 9 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
		$h1 = "PK"
		$s1 = {2e6a730a0020}
		$s2 = {2e6a73ad}
	condition:
            $h1 at 0 and all of ($s*)
}


rule warning_excel_dde_exec {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "Oct 10 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
        	$header_xml = "<?xml version=" nocase wide ascii
		$dde = "instrText>DDE"
	condition:
            $header_xml and $dde
}

rule warning_rtf_objupdate {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 2
		revision = "1"
		date = "Nov 20 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "update RTF object may load malicious content"
	strings:
    	$header_xml = "{\\rt" nocase
		$upd = "\\objupdate" nocase
		
	condition:
		all of them
}

rule warning_powershell_strings {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = false
        rank = 5
        revision = "1"
        date = "Feb 15 2018"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
        tlp = "red"
        sigtype = "cryptam_exploit"
        desc = "Powershell"
    strings:
        $s1 = "powershell.exe"
	$s2 = "-nop -w hidden -encodedcommand"
	$s3 = "Package"
	$s4 = "Ole10Native" wide


    condition:
	3 of them
    }
/* 
 * QuickSand.io - Document malware forensics tool
 *
 * File  quicksand_general.yara  Dec 10 2016
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

rule doc_exploit_ms12_060_toolbar
{
	meta:
		author = "@tylabs"
	strings:
		$a = "MSComctlLib.Toolbar.2"
		$b = {4D53436F6D63746C4C69622E546F6F6C6261722E32}
	condition:
		any of them
}


rule winrar_sfx {
	meta:
		author = "@tylabs"
	strings:
		$u1 = "d:\\Projects\\WinRAR\\SFX\\build\\sfxrar32\\Release\\sfxrar.pdb"
	condition:
		any of them
}


rule this_alt_key
{
	meta:
		author = "@tylabs"
		hash = "821f7ef4349d542f5f34f90b10bcc690"
	strings:
		$a = {79 BA 1E 6F E1 16 79 DF 32 88 FE 29 C9 ED 52 B6 13 4D B3 4C 73 D3 7B 72 D0 24 CF FD 57 FE C7 67 9E 52 7A D3 05 63}
	condition:
		any of them
}

rule this_dbl_xor
{
	meta:
		author = "@tylabs"
		hash = "d85d54434e990e84a28862523c277057"
	strings:
		$a = {86 BB BD A6 F6 A7 5A 46 4D 59 4D 40 0E 4C 41 4F 4C 4C 50 05 44 42 18 4B 4F 55 1C 54 50 1F 74 7E 61 13 59 5A 52 52 }
	condition:
		any of them
}

rule gen_ie_secrets {
	meta:
		author = "@tylabs"
 	strings:
 		$a = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
 	condition:
 		all of them
}

rule compiler_midl
{
	meta:
		author = "@tylabs"

        strings:
		$s1 = "Created by MIDL version " wide
	condition:
		any of them
}



rule compression_ucl
{
	meta:
		author = "@tylabs"
        strings:
                $s1 = "UCL data compression library." wide
		$s2 = "Id: UCL version:" wide
	condition:
		all of them
}

rule coms_openssl
{
	meta:
		author = "@tylabs"
	strings:
                $s1 = ".\\ssl\\ssl_lib.c"
		$s2 = ".\\ssl\\ssl_sess.c"
		$s3 = "part of OpenSSL"
	condition:
		all of them
}




rule netcat
{
	meta:
		author = "@tylabs"
    		comment = "tool"

	strings:
    		$a = "Failed to create ReadShell session thread, error = %s"
    		$b = "Failed to create shell stdout pipe, error = %s"
 
	condition:
   		all of them 
}


rule apt_template_tran_duy_linh
{
	meta:
		author = "@tylabs"
          	info = "author"
	strings:
		$auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

	condition:
		$auth
}

rule theme_MH370 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH370" ascii wide nocase fullword
		$callsign2 = "MAS370" ascii wide nocase fullword
		$desc1 = "Flight 370" ascii wide nocase fullword

	condition:
		any of them
}

rule theme_MH17 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH17" ascii wide nocase fullword
		$callsign2 = "MAS17" ascii wide nocase fullword
		$desc1 = "malaysia airlines flight 17" ascii wide nocase

	condition:
		any of them
}



rule openxml_remote_content
{
	meta:
		author = "@tylabs"
		ref = "https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Crenshaw"
		date = "Aug 10 2014"
		hash = "63ea878a48a7b0459f2e69c46f88f9ef"

	strings: 
		$a = "schemas.openxmlformats.org" ascii nocase
		$b = "TargetMode=\"External\"" ascii nocase

	condition:
		all of them
}


rule office97_guid
{
	meta:
		author = "@tylabs"
		ref = "http://search.lores.eu/fiatlu/GUIDnumber.html"
		
	strings:
		$a = "_PID_GUID"
		$magic = {D0 CF 11 E0}

	condition:
		$magic at 0 and $a
}

rule InceptionRTF {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "}}PT@T"
		$b = "XMLVERSION \"3.1.11.5604.5606"
		$c = "objclass Word.Document.12}\\objw9355" 
	condition:
		all of them
}

rule mime_mso
{
	meta:
		author = "@tylabs"
		comment = "mime mso detection"
	strings:
		$a="application/x-mso"
		$b="MIME-Version"
		$c="ocxstg001.mso"
		$d="?mso-application"
	condition:
		$a and $b or $c or $d
}


rule mime_mso_embedded_SuppData
{
	meta:
		author = "@tylabs"
    		comment = "mime mso office obfuscation"
    		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
		$a = "docSuppData"
		$b = "binData"
		$c = "schemas.microsoft.com"

	condition:
		all of them
}


rule mime_mso_embedded_ole
{
	meta:
		author = "@tylabs"
    		comment = "mime mso office obfuscation"
    		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
    		$a = "docOleData"
    		$b = "binData"
    		$c = "schemas.microsoft.com"
 
	condition:
    		all of them
}




rule mime_mso_vba_macros
{
	meta:
		author = "@tylabs"
		comment = "mime mso office obfuscation"
		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
		$a = "macrosPresent=\"yes\""
		$b = "schemas.microsoft.com"

	condition:
		all of them
}

rule ExOleObjStgCompressedAtom { 
	meta:
		author = "@tylabs"
		date   = "2015 06 09"
		ref    = "http://www.threatgeek.com/2015/06/fidelis-threat-advisory-1017-phishing-in-plain-sight.html"
		hashes = "2303c3ad273d518cbf11824ec5d2a88e"
	strings: 
		$head = { 10 00 11 10 }
		$magic = { D0 CF 11 E0 }
		$openxml = "Package0" wide
	
	condition:
		($magic at 0) and $head and $openxml
}



rule office_encryption { 
	meta:
		author = "@tylabs"
		date   = "2015 06 22"
	strings: 
		$sig1 = "Microsoft Base Cryptography Provider v" wide
		$sig2 = "EncryptedSummary" wide
		$magic = { D0 CF 11 E0 }
	
	condition:
		($magic at 0) and (1 of ($sig*))

}

/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
import "pe"
rule Possible_Emotet_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed indicators Emotet DLL loaded into memory March 2022"
  strings:
      $htt1 = "MS Shell Dlg" wide
      $mzh = "This program cannot be run in DOS mode"
  condition:
      (pe.imphash() == "066d4e2c6288c042d958ddc93cfa07f1" or pe.imphash() == "	38617efee413c2d5919637769ddb6a9") and $htt1 and $mzh
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Infostealer_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $reggie = /[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\.dll/ wide
      $web = /https?:/ nocase wide
      $negate1 = "saitek" nocase wide
  condition:
      ($reggie and $web) and not $negate1
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Infostealer_PowerShell
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed powershell command strings"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = /\[.\..\]::run\(\)/ nocase
      $b = /\[.\..\]::run\(\)/ nocase wide
      $c = "[Reflection.Assembly]::Load("
      $d = /\[[a-zA-Z0-9\._]{25,45}\]::[a-zA-Z0-9\._]{10,25}\(\)/
  condition:
      ($a or $b) or ($c and $d)
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Jupyter_Infostealer_DLL_October2021
{
  meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "https://squiblydoo.blog/2021/10/17/solarmarker-by-any-other-name/" 
  strings:
      $reggie = /[0-9a-fA-F]{32}\.dll/ wide
      $web = /https?:/ nocase wide
      $path = "appdata" nocase wide
      $rsa = "RSAKeyValue" wide
      $packer = "dzkabr"
      $ps = "System.IO.File" wide
  condition:
      ($reggie and $web and $path) and ($rsa or $packer or $ps)
}
import "pe"

rule Redline_Detection
{
   meta:
      author = "Lucas Acha (http://www.lukeacha.com)"
      description = "Observed with Redline Stealer injected DLL"
  strings:
      $htt1 = "System.Reflection.ReflectionContext" wide
      $htt7 = "System.Runtime.Remoting" ascii
      $htt8 = "AesCryptoServiceProvider" ascii
      $htt9 = "DownloadString" ascii
      $htt10 = "CheckRemoteDebuggerPresent" ascii
      $htt6 = "System.IO.Compression" ascii
      $mzh = "This program cannot be run in DOS mode"
      $neg = "rsEngine.Utilities.dll" wide
  condition:
      (pe.imphash() == "dae02f32a21e03ce65412f6e56942daa") and all of ($htt*) and $mzh and filesize > 500KB and not $neg
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
import "pe"
rule Multifamily_RAT_Detection
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Generic Detection for multiple RAT families, PUPs, Packers and suspicious executables"
  strings:
      $htt1 = "WScript.Shell" wide
      $htt2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
      $htt3 = "\\nuR\\noisreVtnerruC\\swodniW" wide
      $htt4 = "SecurityCenter2" wide
      $htt5 = ":ptth" wide
      $htt6 = ":sptth" wide
      $htt7 = "System.Reflection" ascii
      $htt8 = "ConfuserEx" ascii
      $htt9 = ".NET Framework 4 Client Profile" ascii
      $htt10 = "CreateEncryptor" ascii
      $mzh = "This program cannot be run in DOS mode"
  condition:
      (pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e" or pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744") and 3 of ($htt*) and $mzh
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Dropped_File
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = "solarmarker.dat" nocase wide
  condition:
      all of them
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
  
*/
rule solarmarker_March2022
{

  meta:
      author = "Lucas Acha (http://www.lukeacha.com)"
      description = "observed strings with malicious DLL loaded by Soalrmarker Malware during March 2022 campaign"
      reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $off1 = { 59 d1 8c ?? 00 00 }
      $hex2 = { 6c 58 11 07 6c 58 }
      $hex3 = { 6c 5a 58 11 5c }
      $hex4 = { 6c 59 11 ed 6c ?? }
      $hex5 = { 6c 58 fe 0c 2? 01 6c }
      $hex6 = { 6c 58 11 07 11 08 }
      $hex7 = { 6c 5a 58 11 0? 6c }
  condition:
     ($off1 in (0x17d0..0x1a20) and 2 of ($hex*) and $mz at 0)
}
import "pe"
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Solarmarker_Dropper
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Based on import hash and string observations with March 2022 solarmarker dropper"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $htt1 = "PowerShell"
	    $htt2 = "System.Collections.ObjectModel"
      $htt3 = "System.Management.Automation"
      $htt4 = ".NETFramework"
      $htt5 = "HashAlgorithm"
  condition:
      pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e" and 3 of ($htt*)
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Solarmarker_Packer
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed possible packer in hexdump at specific offset ranges."
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $c = { 68 6b 65 79 00 70 61 63 6b 65 64 00 }
  condition:
      $c in (0x10000..0x30000) or $c in (0x50000..0x60000) or $c in (0x70000..0x90000)
}

/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Solarmarker_Packer_2
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "another version showing observed possible packer in hexdump at specific offset ranges."
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $off1 = { 68 6b 65 79 00 46 72 6f 6d 42 61 73 65 36 34} 
      $off2 = { 70 61 63 6b 65 64 }
  condition:
     $off1 in (0x26000..0x32000) and $off2 in (0x26000..0x32000) and $mz at 0
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Solarmarker_Packer_Strings
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed ASCII and Wide strings of obfuscated solarmarker dll"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $wstring1 = "zkabsr" wide
      $astring1 = "keyPath" ascii
      $astring2 = "hSection" ascii
      $astring3 = "valueName" ascii
      $astring4 = "StaticArrayInitTypeSize" ascii
      $astring5 = "KeyValuePair" ascii
  condition:
     $mz at 0 and $wstring1 and 1 of ($astring*)
}

/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Solarmarker_Packer_May_2023
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "another version showing observed possible packer in hexdump at specific offset ranges."
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $off1 = { 41 1? ?? 00 ?? 00 61 1? ?? 00 }
      $off2 = { 41 0? 23 00 ?? 00 61 0? 23 00 }
      $astring1 = "IDisposable" ascii
      $wstring1 = "0.0.0.0" wide
  condition:
     ($off1 in (0x80000..0x9FFFF) or $off2 in (0x72000..0x9FFFF)) and $astring1 and $wstring1 and $mz at 0 and filesize<1MB
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Suspicious_PS_Strings
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed set of strings which are likely malicious, observed with Jupyter malware. "
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
    strings:
        $a = "windowstyle=7" nocase
        $b = "[system.io.file]:" nocase
        $c = ":readallbytes" nocase
        $d = "system.text.encoding]::" nocase
        $e = "utf8.getstring" nocase
        $f = "([system.convert]::" nocase
        $g = "frombase64string" nocase
        $h = "[system.reflection.assembly]::load" nocase
        $i = "-bxor" nocase
    condition:
        6 of them
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
import "pe"
rule suspicious_obfuscated_script_detection
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed strings with suspicious AutoIT scripts"
  strings:
      $a = "NoTrayIcon" ascii
      $b = "Global" ascii
      $c = "StringTrimLeft" ascii
      $d = "StringTrimRight" ascii
      $e = "StringReverse" ascii
  condition:
      all of them and filesize < 3MB
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule vbs_downloader_jan2021
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "VBS downloader campaign appearing January 2021"
	referencs = "http://security5magics.blogspot.com/2021/01/new-vbs-downloader-variant-observed.html"
  strings:
      $a = "vbSystemModal" nocase
      $b = "programdata" nocase
      $c = "regsvr32" nocase
      $d = "objStream.Open" nocase
      $e = "responseBody" nocase
      $f = "a.setOption 2,13056" nocase
  condition:
      ($a and $b and $c and $d and $e) or $f
}
/*
    Suspicious Powershell in weaponized word documents
    Reference: 5c6148619abb10bb3789dcfb32f759a6
*/
rule suspicious_powershell_winword
{
    strings:
        $a = {D0 CF 11 E0 A1 B1 1A E1 00 00 00 00 00}
        $b = {4D 69 63 72 6F 73 6F 66 74 20 4F 66 66 69 63 65 20 57 6F 72 64 00}
        $c = "powershell -e" nocase
    condition:
        all of them
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule possible_wwlib_hijacking
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed with campaigns such as APT32, this attempts to look for the archive files such as RAR."
        reference = "040abac56542a2e0f384adf37c8f95b2b6e6ce3a0ff969e3c1d572e6b4053ff3" 
    strings:
        $a = "/wwlib.dll"
        $neg1 = "This program cannot be run in DOS mode"
        $neg2 = "Doctor Web"
        $neg3 = "pandasecurity.com"
    condition:
        $a and not any of ($neg1,$neg2,$neg3)
}
