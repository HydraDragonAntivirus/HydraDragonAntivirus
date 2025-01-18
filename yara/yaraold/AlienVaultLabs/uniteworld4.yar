
rule LIGHTDART_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "ret.log" wide ascii
                $s2 = "Microsoft Internet Explorer 6.0" wide ascii
                $s3 = "szURL Fail" wide ascii
                $s4 = "szURL Successfully" wide ascii
                $s5 = "%s&sdate=%04ld-%02ld-%02ld" wide ascii
        condition:
                all of them
}

rule AURIGA_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
        condition:
                all of them
}

rule AURIGA_driver_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Services\\riodrv32" wide ascii
                $s2 = "riodrv32.sys" wide ascii
                $s3 = "svchost.exe" wide ascii
                $s4 = "wuauserv.dll" wide ascii
                $s5 = "arp.exe" wide ascii
                $pdb = "projects\\auriga" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule BANGAT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
                $s8 = "end      binary output" wide ascii
                $s9 = "XriteProcessMemory" wide ascii
                $s10 = "IE:Password-Protected sites" wide ascii
                $s11 = "pstorec.dll" wide ascii

        condition:
                all of them
}

rule BISCUIT_GREENCAT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "zxdosml" wide ascii
                $s2 = "get user name error!" wide ascii
                $s3 = "get computer name error!" wide ascii
                $s4 = "----client system info----" wide ascii
                $s5 = "stfile" wide ascii
                $s6 = "cmd success!" wide ascii

        condition:
                all of them
}

rule BOUNCER_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
                $s2 = "IDR_DATA%d" wide ascii

                $s3 = "asdfqwe123cxz" wide ascii
                $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

        condition:
                ($s1 and $s2) or ($s3 and $s4)

}

rule BOUNCER_DLL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "new_connection_to_bounce():" wide ascii
                $s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

        condition:
                all of them
}

rule CALENDAR_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "content" wide ascii
                $s2 = "title" wide ascii
                $s3 = "entry" wide ascii
                $s4 = "feed" wide ascii
                $s5 = "DownRun success" wide ascii
                $s6 = "%s@gmail.com" wide ascii
                $s7 = "<!--%s-->" wide ascii

                $b8 = "W4qKihsb+So=" wide ascii
                $b9 = "PoqKigY7ggH+VcnqnTcmhFCo9w==" wide ascii
                $b10 = "8oqKiqb5880/uJLzAsY=" wide ascii

        condition:
                all of ($s*) or all of ($b*)
}

rule COMBOS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla4.0 (compatible; MSIE 7.0; Win32)" wide ascii
                $s2 = "Mozilla5.1 (compatible; MSIE 8.0; Win32)" wide ascii
                $s3 = "Delay" wide ascii
                $s4 = "Getfile" wide ascii
                $s5 = "Putfile" wide ascii
                $s6 = "---[ Virtual Shell]---" wide ascii
                $s7 = "Not Comming From Our Server %s." wide ascii


        condition:
                all of them
}

rule DAIRY_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE 7.0;)" wide ascii
                $s2 = "KilFail" wide ascii
                $s3 = "KilSucc" wide ascii
                $s4 = "pkkill" wide ascii
                $s5 = "pklist" wide ascii


        condition:
                all of them
}

rule GLOOXMAIL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule GOGGLES_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule HACKSFASE1_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = {cb 39 82 49 42 be 1f 3a}

        condition:
                all of them
}

rule HACKSFASE2_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Send to Server failed." wide ascii
                $s2 = "HandShake with the server failed. Error:" wide ascii
                $s3 = "Decryption Failed. Context Expired." wide ascii

        condition:
                all of them
}

rule KURTON_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE8.0; Windows NT 5.1)" wide ascii
                $s2 = "!(*@)(!@PORT!(*@)(!@URL" wide ascii
                $s3 = "MyTmpFile.Dat" wide ascii
                $s4 = "SvcHost.DLL.log" wide ascii

        condition:
                all of them
}

rule LONGRUN_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" wide ascii
                $s2 = "%s\\%c%c%c%c%c%c%c" wide ascii
                $s3 = "wait:" wide ascii
                $s4 = "Dcryption Error! Invalid Character" wide ascii

        condition:
                all of them
}

rule MACROMAIL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "svcMsn.dll" wide ascii
                $s2 = "RundllInstall" wide ascii
                $s3 = "Config service %s ok." wide ascii
                $s4 = "svchost.exe" wide ascii

        condition:
                all of them
}

rule MANITSME_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Install an Service hosted by SVCHOST." wide ascii
                $s2 = "The Dll file that to be released." wide ascii
                $s3 = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
                $s4 = "svchost.exe" wide ascii

                $e1 = "Man,it's me" wide ascii
                $e2 = "Oh,shit" wide ascii
                $e3 = "Hallelujah" wide ascii
                $e4 = "nRet == SOCKET_ERROR" wide ascii

                $pdb1 = "rouji\\release\\Install.pdb" wide ascii
                $pdb2 = "rouji\\SvcMain.pdb" wide ascii

        condition:
                (all of ($s*)) or (all of ($e*)) or $pdb1 or $pdb2
}

rule MINIASP_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "miniasp" wide ascii
                $s2 = "wakeup=" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "device_input.asp?device_t=" wide ascii


        condition:
                all of them
}

rule NEWSREELS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" wide ascii
                $s2 = "name=%s&userid=%04d&other=%c%s" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "noclient" wide ascii
                $s6 = "wait" wide ascii
                $s7 = "active" wide ascii
                $s8 = "hello" wide ascii


        condition:
                all of them
}

rule SEASALT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98) KSMM" wide ascii
                $s2 = "upfileok" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "upfileer" wide ascii
                $s5 = "fxftest" wide ascii


        condition:
                all of them
}

rule STARSYPOUND_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "*(SY)# cmd" wide ascii
                $s2 = "send = %d" wide ascii
                $s3 = "cmd.exe" wide ascii
                $s4 = "*(SY)#" wide ascii


        condition:
                all of them
}

rule SWORD_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "@***@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>>>" wide ascii
                $s2 = "sleep:" wide ascii
                $s3 = "down:" wide ascii
                $s4 = "*========== Bye Bye ! ==========*" wide ascii


        condition:
                all of them
}


rule thequickbrow_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "thequickbrownfxjmpsvalzydg" wide ascii


        condition:
                all of them
}


rule TABMSGSQL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "letusgohtppmmv2.0.0.1" wide ascii
                $s2 = "Mozilla/4.0 (compatible; )" wide ascii
                $s3 = "filestoc" wide ascii
                $s4 = "filectos" wide ascii
                $s5 = "reshell" wide ascii

        condition:
                all of them
}

rule CCREWBACK1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "postvalue" wide ascii
    $b = "postdata" wide ascii
    $c = "postfile" wide ascii
    $d = "hostname" wide ascii
    $e = "clientkey" wide ascii
    $f = "start Cmd Failure!" wide ascii
    $g = "sleep:" wide ascii
    $h = "downloadcopy:" wide ascii
    $i = "download:" wide ascii
    $j = "geturl:" wide ascii
    $k = "1.234.1.68" wide ascii

  condition:
    4 of ($a,$b,$c,$d,$e) or $f or 3 of ($g,$h,$i,$j) or $k
}

rule TrojanCookies_CCREW
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "sleep:" wide ascii
    $b = "content=" wide ascii
    $c = "reqpath=" wide ascii
    $d = "savepath=" wide ascii
    $e = "command=" wide ascii


  condition:
    4 of ($a,$b,$c,$d,$e)
}

rule GEN_CCREW1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "W!r@o#n$g" wide ascii
    $b = "KerNel32.dll" wide ascii

  condition:
    any of them
}

rule Elise
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SetElise.pdb" wide ascii

  condition:
    $a
}

rule EclipseSunCloudRAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Eclipse_A" wide ascii
    $b = "\\PJTS\\" wide ascii
    $c = "Eclipse_Client_B.pdb" wide ascii
    $d = "XiaoME" wide ascii
    $e = "SunCloud-Code" wide ascii
    $f = "/uc_server/data/forum.asp" wide ascii

  condition:
    any of them
}

rule MoonProject
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Serverfile is smaller than Clientfile" wide ascii
    $b = "\\M tools\\" wide ascii
    $c = "MoonDLL" wide ascii
        $d = "\\M tools\\" wide ascii

  condition:
    any of them
}

rule ccrewDownloader1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = {DD B5 61 F0 20 47 20 57 D6 65 9C CB 31 1B 65 42}

  condition:
    any of them
}

rule ccrewDownloader2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "3gZFQOBtY3sifNOl" wide ascii
        $b = "docbWUWsc2gRMv9HN7TFnvnKcrWUUFdAEem9DkqRALoD" wide ascii
        $c = "6QVSOZHQPCMc2A8HXdsfuNZcmUnIqWrOIjrjwOeagILnnScxadKEr1H2MZNwSnaJ" wide ascii

  condition:
    any of them
}


rule ccrewMiniasp
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "MiniAsp.pdb" wide ascii
    $b = "device_t=" wide ascii

  condition:
    any of them
}


rule ccrewSSLBack2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = {39 82 49 42 BE 1F 3A}

  condition:
    any of them
}

rule ccrewSSLBack3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SLYHKAAY" wide ascii

  condition:
    any of them
}


rule ccrewSSLBack1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!@#%$^#@!" wide ascii
    $b = "64.91.80.6" wide ascii

  condition:
    any of them
}

rule ccrewDownloader3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "ejlcmbv" wide ascii
        $b = "bhxjuisv" wide ascii
        $c = "yqzgrh" wide ascii
        $d = "uqusofrp" wide ascii
        $e = "Ljpltmivvdcbb" wide ascii
        $f = "frfogjviirr" wide ascii
        $g = "ximhttoskop" wide ascii
  condition:
    4 of them
}


rule ccrewQAZ
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!QAZ@WSX" wide ascii

  condition:
    $a
}

rule metaxcd
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "<meta xcd=" wide ascii

  condition:
    $a
}

rule MiniASP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

strings:
    $KEY = { 71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A }
    $PDB = "MiniAsp.pdb" nocase wide ascii

condition:
    any of them
}

rule DownloaderPossibleCCrew
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "%s?%.6u" wide ascii
    $b = "szFileUrl=%s" wide ascii
    $c = "status=%u" wide ascii
    $d = "down file success" wide ascii
        $e = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" wide ascii

  condition:
    all of them
}

rule APT1_MAPIGET
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "%s\\Attachment.dat" wide ascii
        $s2 = "MyOutlook" wide ascii
        $s3 = "mail.txt" wide ascii
        $s4 = "Recv Time:" wide ascii
        $s5 = "Subject:" wide ascii

    condition:
        all of them
}

rule APT1_LIGHTBOLT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "bits.exe" wide ascii
        $str2 = "PDFBROW" wide ascii
        $str3 = "Browser.exe" wide ascii
        $str4 = "Protect!" wide ascii
    condition:
        2 of them
}

rule APT1_GETMAIL
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $stra1 = "pls give the FULL path" wide ascii
        $stra2 = "mapi32.dll" wide ascii
        $stra3 = "doCompress" wide ascii

        $strb1 = "getmail.dll" wide ascii
        $strb2 = "doCompress" wide ascii
        $strb3 = "love" wide ascii
    condition:
        all of ($stra*) or all of ($strb*)
}

rule APT1_GDOCUPLOAD
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "name=\"GALX\"" wide ascii
        $str2 = "User-Agent: Shockwave Flash" wide ascii
        $str3 = "add cookie failed..." wide ascii
        $str4 = ",speed=%f" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_Y21K
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Y29ubmVjdA" wide ascii // connect
        $2 = "c2xlZXA" wide ascii // sleep
        $3 = "cXVpdA" wide ascii // quit
        $4 = "Y21k" wide ascii // cmd
        $5 = "dW5zdXBwb3J0" wide ascii // unsupport
    condition:
        4 of them
}

rule APT1_WEBC2_YAHOO
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $http1 = "HTTP/1.0" wide ascii
        $http2 = "Content-Type:" wide ascii
        $uagent = "IPHONE8.5(host:%s,ip:%s)" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_UGX
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $persis = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide ascii
        $exe = "DefWatch.exe" wide ascii
        $html = "index1.html" wide ascii
        $cmd1 = "!@#tiuq#@!" wide ascii
        $cmd2 = "!@#dmc#@!" wide ascii
        $cmd3 = "!@#troppusnu#@!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_TOCK
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "InprocServer32" wide ascii
        $2 = "HKEY_PERFORMANCE_DATA" wide ascii
        $3 = "<!---[<if IE 5>]id=" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_TABLE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $msg1 = "Fail To Execute The Command" wide ascii
        $msg2 = "Execute The Command Successfully" wide ascii
        $gif1 = /\w+\.gif/
        $gif2 = "GIF89" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_RAVE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "iniet.exe" wide ascii
        $2 = "cmd.exe" wide ascii
        $3 = "SYSTEM\\CurrentControlSet\\Services\\DEVFS" wide ascii
        $4 = "Device File System" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_QBP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "2010QBP" wide ascii
        $2 = "adobe_sl.exe" wide ascii
        $3 = "URLDownloadToCacheFile" wide ascii
        $4 = "dnsapi.dll" wide ascii
        $5 = "urlmon.dll" wide ascii
    condition:
        4 of them
}

rule APT1_WEBC2_KT3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "*!Kt3+v|" wide ascii
        $2 = " s:" wide ascii
        $3 = " dne" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_HEAD
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Ready!" wide ascii
        $2 = "connect ok" wide ascii
        $3 = "WinHTTP 1.0" wide ascii
        $4 = "<head>" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_GREENCAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "reader_sl.exe" wide ascii
        $2 = "MS80547.bat" wide ascii
        $3 = "ADR32" wide ascii
        $4 = "ControlService failed!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_DIV
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "3DC76854-C328-43D7-9E07-24BF894F8EF5" wide ascii
        $2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $3 = "Hello from MFC!" wide ascii
        $4 = "Microsoft Internet Explorer" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_CSON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $httpa1 = "/Default.aspx?INDEX=" wide ascii
        $httpa2 = "/Default.aspx?ID=" wide ascii
        $httpb1 = "Win32" wide ascii
        $httpb2 = "Accept: text*/*" wide ascii
        $exe1 = "xcmd.exe" wide ascii
        $exe2 = "Google.exe" wide ascii
    condition:
        1 of ($exe*) and 1 of ($httpa*) and all of ($httpb*)
}

rule APT1_WEBC2_CLOVER
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $msg1 = "BUILD ERROR!" wide ascii
        $msg2 = "SUCCESS!" wide ascii
        $msg3 = "wild scan" wide ascii
        $msg4 = "Code too clever" wide ascii
        $msg5 = "insufficient lookahead" wide ascii
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; SV1)" wide ascii
        $ua2 = "Mozilla/5.0 (Windows; Windows NT 5.1; en-US; rv:1.8.0.12) Firefox/1.5.0.12" wide ascii
    condition:
        2 of ($msg*) and 1 of ($ua*)
}

rule APT1_WEBC2_BOLID
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $vm = "VMProtect" wide ascii
        $http = "http://[c2_location]/[page].html" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_ADSPACE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "<!---HEADER ADSPACE style=" wide ascii
        $2 = "ERSVC.DLL" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_AUSOV
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "ntshrui.dll" wide ascii
        $2 = "%SystemRoot%\\System32\\" wide ascii
        $3 = "<!--DOCHTML" wide ascii
        $4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" wide ascii
        $5 = "Ausov" wide ascii
    condition:
        4 of them
}

rule APT1_WARP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $err1 = "exception..." wide ascii
        $err2 = "failed..." wide ascii
        $err3 = "opened..." wide ascii
        $exe1 = "cmd.exe" wide ascii
        $exe2 = "ISUN32.EXE" wide ascii
    condition:
        2 of ($err*) and all of ($exe*)
}

rule APT1_TARSIP_ECLIPSE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "\\pipe\\ssnp" wide ascii
        $2 = "toobu.ini" wide ascii
        $3 = "Serverfile is not bigger than Clientfile" wide ascii
        $4 = "URL download success" wide ascii
    condition:
        3 of them
}

rule APT1_TARSIP_MOON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "\\XiaoME\\SunCloud-Code\\moon" wide ascii
        $s2 = "URL download success!" wide ascii
        $s3 = "Kugoosoft" wide ascii
        $msg1 = "Modify file failed!! So strange!" wide ascii
        $msg2 = "Create cmd process failed!" wide ascii
        $msg3 = "The command has not been implemented!" wide ascii
        $msg4 = "Runas success!" wide ascii
        $onec1 = "onec.php" wide ascii
        $onec2 = "/bin/onec" wide ascii
    condition:
        1 of ($s*) and 1 of ($msg*) and 1 of ($onec*)
}

private rule APT1_payloads
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii
    condition:
        1 of them
}

private rule APT1_RARSilent_EXE_PDF
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $winrar1 = "WINRAR.SFX" wide ascii
        $winrar2 = ";The comment below contains SFX script commands" wide ascii
        $winrar3 = "Silent=1" wide ascii

        $str1 = /Setup=[\s\w\"]+\.(exe|pdf|doc)/
        $str2 = "Steup=\"" wide ascii
    condition:
        all of ($winrar*) and 1 of ($str*)
}

rule APT1_aspnetreport
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $url = "aspnet_client/report.asp" wide ascii
        $param = "name=%s&Gender=%c&Random=%04d&SessionKey=%s" wide ascii
    condition:
        $url and $param and APT1_payloads
}

rule APT1_Revird_svc
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dll1 = "nwwwks.dll" wide ascii
        $dll2 = "rdisk.dll" wide ascii
        $dll3 = "skeys.dll" wide ascii
        $dll4 = "SvcHost.DLL.log" wide ascii
        $svc1 = "InstallService" wide ascii
        $svc2 = "RundllInstallA" wide ascii
        $svc3 = "RundllUninstallA" wide ascii
        $svc4 = "ServiceMain" wide ascii
        $svc5 = "UninstallService" wide ascii
    condition:
        1 of ($dll*) and 2 of ($svc*)
}

rule APT1_letusgo
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $letus = /letusgo[\w]+v\d\d?\./
    condition:
        $letus
}

rule APT1_dbg_mess
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dbg1 = "Down file ok!" wide ascii
        $dbg2 = "Send file ok!" wide ascii
        $dbg3 = "Command Error!" wide ascii
        $dbg4 = "Pls choose target first!" wide ascii
        $dbg5 = "Alert!" wide ascii
        $dbg6 = "Pls press enter to make sure!" wide ascii
        $dbg7 = "Are you sure to " wide ascii
    condition:
        4 of them and APT1_payloads
}

rule APT1_known_malicious_RARSilent
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "Analysis And Outlook.doc\"" wide ascii
        $str2 = "North Korean launch.pdf\"" wide ascii
        $str3 = "Dollar General.doc\"" wide ascii
        $str4 = "Dow Corning Corp.pdf\"" wide ascii
    condition:
        1 of them and APT1_RARSilent_EXE_PDF
}

rule avdetect_procs : avdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Antivirus detection tricks"

	strings:
		$proc2 = "LMon.exe" ascii wide
		$proc3 = "sagui.exe" ascii wide
		$proc4 = "RDTask.exe" ascii wide
		$proc5 = "kpf4gui.exe" ascii wide
		$proc6 = "ALsvc.exe" ascii wide
		$proc7 = "pxagent.exe" ascii wide
		$proc8 = "fsma32.exe" ascii wide
		$proc9 = "licwiz.exe" ascii wide
		$proc10 = "SavService.exe" ascii wide
		$proc11 = "prevxcsi.exe" ascii wide
		$proc12 = "alertwall.exe" ascii wide
		$proc13 = "livehelp.exe" ascii wide
		$proc14 = "SAVAdminService.exe" ascii wide
		$proc15 = "csi-eui.exe" ascii wide
		$proc16 = "mpf.exe" ascii wide
		$proc17 = "lookout.exe" ascii wide
		$proc18 = "savprogress.exe" ascii wide
		$proc19 = "lpfw.exe" ascii wide
		$proc20 = "mpfcm.exe" ascii wide
		$proc21 = "emlproui.exe" ascii wide
		$proc22 = "savmain.exe" ascii wide
		$proc23 = "outpost.exe" ascii wide
		$proc24 = "fameh32.exe" ascii wide
		$proc25 = "emlproxy.exe" ascii wide
		$proc26 = "savcleanup.exe" ascii wide
		$proc27 = "filemon.exe" ascii wide
		$proc28 = "AntiHook.exe" ascii wide
		$proc29 = "endtaskpro.exe" ascii wide
		$proc30 = "savcli.exe" ascii wide
		$proc31 = "procmon.exe" ascii wide
		$proc32 = "xfilter.exe" ascii wide
		$proc33 = "netguardlite.exe" ascii wide
		$proc34 = "backgroundscanclient.exe" ascii wide
		$proc35 = "Sniffer.exe" ascii wide
		$proc36 = "scfservice.exe" ascii wide
		$proc37 = "oasclnt.exe" ascii wide
		$proc38 = "sdcservice.exe" ascii wide
		$proc39 = "acs.exe" ascii wide
		$proc40 = "scfmanager.exe" ascii wide
		$proc41 = "omnitray.exe" ascii wide
		$proc42 = "sdcdevconx.exe" ascii wide
		$proc43 = "aupdrun.exe" ascii wide
		$proc44 = "spywaretermin" ascii wide
		$proc45 = "atorshield.exe" ascii wide
		$proc46 = "onlinent.exe" ascii wide
		$proc47 = "sdcdevconIA.exe" ascii wide
		$proc48 = "sppfw.exe" ascii wide
		$proc49 = "spywat~1.exe" ascii wide
		$proc50 = "opf.exe" ascii wide
		$proc51 = "sdcdevcon.exe" ascii wide
		$proc52 = "spfirewallsvc.exe" ascii wide
		$proc53 = "ssupdate.exe" ascii wide
		$proc54 = "pctavsvc.exe" ascii wide
		$proc55 = "configuresav.exe" ascii wide
		$proc56 = "fwsrv.exe" ascii wide
		$proc57 = "terminet.exe" ascii wide
		$proc58 = "pctav.exe" ascii wide
		$proc59 = "alupdate.exe" ascii wide
		$proc60 = "opfsvc.exe" ascii wide
		$proc61 = "tscutynt.exe" ascii wide
		$proc62 = "pcviper.exe" ascii wide
		$proc63 = "InstLsp.exe" ascii wide
		$proc64 = "uwcdsvr.exe" ascii wide
		$proc65 = "umxtray.exe" ascii wide
		$proc66 = "persfw.exe" ascii wide
		$proc67 = "CMain.exe" ascii wide
		$proc68 = "dfw.exe" ascii wide
		$proc69 = "updclient.exe" ascii wide
		$proc70 = "pgaccount.exe" ascii wide
		$proc71 = "CavAUD.exe" ascii wide
		$proc72 = "ipatrol.exe" ascii wide
		$proc73 = "webwall.exe" ascii wide
		$proc74 = "privatefirewall3.exe" ascii wide
		$proc75 = "CavEmSrv.exe" ascii wide
		$proc76 = "pcipprev.exe" ascii wide
		$proc77 = "winroute.exe" ascii wide
		$proc78 = "protect.exe" ascii wide
		$proc79 = "Cavmr.exe" ascii wide
		$proc80 = "prifw.exe" ascii wide
		$proc81 = "apvxdwin.exe" ascii wide
		$proc82 = "rtt_crc_service.exe" ascii wide
		$proc83 = "Cavvl.exe" ascii wide
		$proc84 = "tzpfw.exe" ascii wide
		$proc85 = "as3pf.exe" ascii wide
		$proc86 = "schedulerdaemon.exe" ascii wide
		$proc87 = "CavApp.exe" ascii wide
		$proc88 = "privatefirewall3.exe" ascii wide
		$proc89 = "avas.exe" ascii wide
		$proc90 = "sdtrayapp.exe" ascii wide
		$proc91 = "CavCons.exe" ascii wide
		$proc92 = "pfft.exe" ascii wide
		$proc93 = "avcom.exe" ascii wide
		$proc94 = "siteadv.exe" ascii wide
		$proc95 = "CavMud.exe" ascii wide
		$proc96 = "armorwall.exe" ascii wide
		$proc97 = "avkproxy.exe" ascii wide
		$proc98 = "sndsrvc.exe" ascii wide
		$proc99 = "CavUMAS.exe" ascii wide
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


rule dbgdetect_funcs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
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

rule dbgdetect_procs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
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

rule dbgdetect_files : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"
	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}

rule undocumentedFPUAtEntryPoint {
strings:
    $fpu1 = {D9 D8}
    $fpu2 = {DF DF}
    $fpu3 = {DF D8}
    $fpu4 = {DC D9}
    $fpu5 = {DF DA}
    $fpu6 = {DF CB}
condition:
    (for any of ($fpu*) : ($ at entrypoint)) or $fpu2 in (entrypoint..entrypoint + 10)
}
rule GeorBotMemory
{
strings:
$a = {53 4F 46 54 57 41 52 45 5C 00 4D 69 63 72 6F 73 6F 66 74 5C 00 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 00 52 75 6E 00 55 53 42 53 45 52 56}
$b = {73 79 73 74 65 6D 33 32 5C 75 73 62 73 65 72 76 2E 65 78 65}
$c = {5C 75 73 62 73 65 72 76 2E 65 78 65}
condition:
$a and ($b or $c)
}
rule GeorBotBinary
{
strings:
$a = {63 72 ?? 5F 30 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

condition:
all of them
}
rule Hangover_ron_babylon
{
  strings:
    $a = "Content-Disposition: form-data; name=\"uploaddir\""
    $b1 = "MBVDFRESCT"
    $b2 = "EMSCBVDFRT"
    $b3 = "EMSFRTCBVD"
    $b4= "sendFile"
    $b5 = "BUGMAAL"
    $b6 = "sMAAL"
    $b7 = "SIMPLE"
    $b8 = "SPLIME"
    $b9 = "getkey.php"
    $b10 = "MBVDFRESCT"
    $b11 = "DSMBVCTFRE"
    $b12 = "MBESCVDFRT"
    $b13 = "TCBFRVDEMS"
    $b14 = "DEMOMAKE"
    $b15 = "DEMO"
    $b16 = "UPHTTP"
    

    $c1 = "F39D45E70395ABFB8D8D2BFFC8BBD152"
    $c2 = "90B452BFFF3F395ABDC878D8BEDBD152"
    $c3 = "FFF3F395A90B452BB8BEDC878DDBD152"
    $c4 = "5A9DCB8FFF3F02B8B45BE39D152"
    $c5 = "5A902B8B45BEDCB8FFF3F39D152"
    $c6 = "78DDB5A902BB8FFF3F398B45BEDCD152"
    $c7 = "905ABEB452BFFFBDC878D83F39DBD152"
    $c8 = "D2BFFC8BBD152F3B8D89D45E70395ABF"
    $c9 = "8765F3F395A90B452BB8BEDC878"
    $c10 = "90ABDC878D8BEDBB452BFFF3F395D152"
    $c11 = "F12BDC94490B452AA8AEDC878DCBD187"
    
  condition:
    $a and (1 of ($b*) or 1 of ($c*))
    
}

rule Hangover_Fuddol {
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}

rule Hangover_UpdateEx {
    strings:
        $a1 = "UpdateEx"
        $a2 = "VBA6.DLL"
        $a3 = "MainEx"
        $a4 = "GetLogs"
        $a5 = "ProMan"
        $a6 = "RedMod"
        
    condition:
        all of them

}

rule Hangover_Tymtin_Degrab {
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}


rule Hangover_Smackdown_Downloader {
    strings:
        $a1 = "DownloadComplete"
        $a2 = "DownloadProgress"
        $a3 = "DownloadError"
        $a4 = "UserControl"
        $a5 = "MSVBVM60.DLL"

        $b1 = "syslide"
        $b2 = "frmMina"
        $b3 = "Soundsman"
        $b4 = "New_upl"
        $b5 = "MCircle"
        $b6 = "shells_DataArrival"
        
    condition:
        3 of ($a*) and 1 of ($b*)

}


rule Hangover_Vacrhan_Downloader {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "VBA6.DLL"
        $a3 = "Timer1"
        $a4 = "Timer2"
        $a5 = "IsNTAdmin"
        
    condition:
        all of them

}


rule Hangover_Smackdown_various {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "NaramGaram"
        $a3 = "vampro"
        $a4 = "AngelPro"
        
        $b1 = "VBA6.DLL"
        $b2 = "advpack"
        $b3 = "IsNTAdmin"
        
        
    condition:
        1 of ($a*) and all of ($b*)

}

rule Hangover_Foler {
    strings:
        $a1 = "\\MyHood"
        $a2 = "UsbP"
        $a3 = "ID_MON"
        
    condition:
        all of them

}

rule Hangover_Appinbot {
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32First"
        $a3 = "Process32Next"
        $a4 = "FIDR/"
        $a5 = "SUBSCRIBE %d"
        $a6 = "CLOSE %d"
        
    condition:
        all of them

}

rule Hangover_Linog {
    strings:
        $a1 = "uploadedfile"
        $a2 = "Error in opening a file.."
        $a3 = "The file could not be opened"
        $a4 = "%sContent-Disposition: form-data; name=\"%s\";filename=\"%s\""

    condition:
        all of them

}


rule Hangover_Iconfall {
    strings:
        $a1 = "iconfall"
        $a2 = "78DDB5A902BB8FFF3F398B45BEDCD152"
        
    condition:
        all of them

}


rule Hangover_Deksila {
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}

rule Hangover_Auspo {
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV2)"
        $a2 = "POWERS"
        $a3 = "AUSTIN"
        
    condition:
        all of them

}

rule Hangover_Slidewin {
    strings:
        $a1 = "[NumLock]"
        $a2 = "[ScrlLock]"
        $a3 = "[LtCtrl]"
        $a4 = "[RtCtrl]"
        $a5 = "[LtAlt]"
        $a6 = "[RtAlt]"
        $a7 = "[HomePage]"
        $a8 = "[MuteOn/Off]"
        $a9 = "[VolDn]"
        $a10 = "[VolUp]"
        $a11 = "[Play/Pause]"
        $a12 = "[MailBox]"
        $a14 = "[Calc]"
        $a15 = "[Unknown]"
        
    condition:
        all of them

}


rule Hangover_Gimwlog {
    strings:
        $a1 = "file closed---------------------"
        $a2 = "new file------------------"
        $a3 = "md C:\\ApplicationData\\Prefetch\\"
        
    condition:
        all of them

}


rule Hangover_Gimwup {
    strings:
        $a1 = "=======inside while==========="
        $a2 = "scan finished"
        $a3 = "logFile.txt"
        
    condition:
        all of them

}

rule Hangover2_Downloader {

  strings:

    $a = "WinInetGet/0.1" wide ascii

    $b = "Excep while up" wide ascii

    $c = "&file=" wide ascii

    $d = "&str=" wide ascii

    $e = "?cn=" wide ascii

  condition:

    all of them
}

rule Hangover2_stealer {

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}

rule Hangover2_backdoor_shell {

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}

rule Hangover2_Keylogger {

  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > " wide ascii

    $c = "Global\\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them
}

rule leverage_a
{
	meta:
		author = "earada@alienvault.com"
		version = "1.0"
		description = "OSX/Leverage.A"
		date = "2013/09"
	strings:
		$a1 = "ioreg -l | grep \"IOPlatformSerialNumber\" | awk -F"
		$a2 = "+:Users:Shared:UserEvent.app:Contents:MacOS:"
		$a3 = "rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'"
		$script1 = "osascript -e 'tell application \"System Events\" to get the hidden of every login item'"
		$script2 = "osascript -e 'tell application \"System Events\" to get the name of every login item'"
		$script3 = "osascript -e 'tell application \"System Events\" to get the path of every login item'"
		$properties = "serverVisible \x00"
	condition:
		all of them
}

rule Careto {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto generic malware signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:

		/* General */
		$name1 = "Careto" ascii wide
		$s_1 = "GetSystemReport" ascii wide
		$s_2 = "SystemReport.txt" ascii wide
		$s_3 = /URL_AUX\w*=/ ascii wide
		$s_4 = /CaretoPruebas.+release/

		/* Certificate */
		$sign_0 = "Sofia"
		$sign_1 = "TecSystem Ltd"
		$sign_2 = "<<<Obsolete>>>" wide

		/* Encryption keys */
		$rc4_1 = "!$7be&.Kaw-12[}" ascii wide
		$rc4_2 = "Caguen1aMar" ascii wide
		/* http://laboratorio.blogs.hispasec.com/2014/02/analisis-del-algoritmo-de-descifrado.html */
		$rc4_3 = {8d 85 86 8a 8f 80 88 83 8d 82 88 85 86 8f 8f 87 8d 82 83 82 8c 8e 83 8d 89 82 86 87 82 83 83 81}

		/* Decryption routine fragment */
		$dec_1 = {8b 4d 08 0f be 04 59 0f be 4c 59 01 2b c7 c1 e0 04 2b cf 0b c1 50 8d 85 f0 fe ff ff}
		$dec_2 = {8b 4d f8 8b 16 88 04 11 8b 06 41 89 4d f8 c6 04 01 00 43 3b 5d fc}

	condition:
		$name1 and (any of ($s_*)) or all of ($sign_*) or any of ($rc4_*) or all of ($dec_*)
}

rule Careto_SGH {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto SGH component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$m1 = "PGPsdkDriver" ascii wide fullword
		$m2 = "jpeg1x32" ascii wide fullword
		$m3 = "SkypeIE6Plugin" ascii wide fullword
		$m4 = "CDllUninstall" ascii wide fullword
	condition:
		2 of them
}

rule Careto_OSX_SBD {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto OSX component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		/* XORed "/dev/null strdup() setuid(geteuid())" */
		$1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}
	condition:
		all of them
}

rule Careto_CnC {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto CnC communication signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$1 = "cgi-bin/commcgi.cgi" ascii wide
		$2 = "Group" ascii wide
		$3 = "Install" ascii wide
		$4 = "Bn" ascii wide
	condition:
		all of them
}

rule Careto_CnC_domains {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto known command and control domains"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$1 = "linkconf.net" ascii wide nocase
		$2 = "redirserver.net" ascii wide nocase
		$3 = "swupdt.com" ascii wide nocase
	condition:
		any of them
}


rule sandboxdetect_misc : sandboxdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
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
rule sshd_liblzma_vulnerability_check
{
    meta:
        description = "Check for specific function signature in liblzma used by sshd indicating potential compromise"
        author = "byinarie"
        reference = "CVE-2024-3094"

    strings:
        $signature = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 }

    condition:
        $signature
}
// https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83

// One way to find PE files that start at offset 0 and have a single byte xor
// key.
rule single_byte_xor_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for single byte xor of a PE starting at offset 0"
  strings:
    $b = "PE\x00\x00" xor(0x01-0xff)
  condition:
    $b at uint32(0x3c) ^ (uint32(@b[1]) ^ 0x00004550) and
    (uint16(0x00) ^ (uint16(@b[1]) ^ 0x4550)) == 0x5a4d
}

// This detects PE files at offset 0 with a 2 byte xor key
// Interesting point: the two_byte rule also detects the one byte rule because
// a one byte xor key is the same as a two byte xor key where both bytes are
// identical. ;)
rule two_byte_xor_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for 2 byte xor of a PE starting at offset 0"
  condition:
    uint16(0) != 0x5a4d and
    uint32((uint16(0x3c) ^ (uint16(0) ^ 0x5a4d)) | ((uint16(0x3e) ^ (uint16(0) ^ 0x5a4d)) << 16)) ^ ((uint16(0) ^ 0x5a4d) | ((uint16(0) ^ 0x5a4d) << 16)) == 0x00004550
}

// Here is a rule that detects 4 byte XOR keys, but it requires that the dwords
// at 0x24 and 0x28 are NULL in the original binary, which is usually true.
rule four_byte_xor_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for 4 byte xor of a PE starting at offset 0"
  condition:
    uint16(0) != 0x5a4d and
    uint32(0x28) != 0x00000000 and
    uint32(0x28) == uint32(0x2c) and
    uint32(uint32(0x3c) ^ uint32(0x28)) ^ uint32(0x28) == 0x00004550
}

// Here is a rule that detects single byte incrementing xor of a PE starting at
// offset 0:
rule single_byte_xor_incr_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for single byte incrementing xor of a PE starting at offset 0"
  condition:
    uint16(0) != 0x5a4d and
    uint8(0) ^ 0x4d == ((uint8(1) ^ 0x5a) - 1) & 0xff and
    uint32(
      uint32(0x3c) ^ (
        (uint8(0) ^ 0x4d) + 0x3c & 0xff |
        ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
        ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
        ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
      )
    ) ^ (
      (uint8(0) ^ 0x4d) + (
        uint32(0x3c) ^ (
          (uint8(0) ^ 0x4d) + 0x3c & 0xff |
          ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
          ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
          ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
        )
      ) & 0xff |
      ((
        (uint8(0) ^ 0x4d) + (
          uint32(0x3c) ^ (
            (uint8(0) ^ 0x4d) + 0x3c & 0xff |
            ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
            ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
            ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
          )
        ) + 1
      ) & 0xff) << 8 |
      ((
        (uint8(0) ^ 0x4d) + (
          uint32(0x3c) ^ (
            (uint8(0) ^ 0x4d) + 0x3c & 0xff |
            ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
            ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
            ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
          )
        ) + 2
      ) & 0xff) << 16 |
      ((
        (uint8(0) ^ 0x4d) + (
          uint32(0x3c) ^ (
            (uint8(0) ^ 0x4d) + 0x3c |
            ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
            ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
            ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
          )
        ) + 3
      ) & 0xff) << 24
    ) == 0x00004550
}import "pe"

rule file_pe_header {
    meta:
        description = "Finds PE file MZ header as uint16"
        last_modified = "2024-01-01"
        author = "@petermstewart"
        DaysofYara = "1/100"

    condition:
        uint16(0) == 0x5a4d
}

rule file_elf_header {
    meta:
        description = "Matches ELF file \x7fELF header as uint32"
        last_modified = "2024-01-02"
        author = "@petermstewart"
        DaysofYara = "2/100"

    condition:
        uint32(0) == 0x464c457f
}

rule file_macho_header {
    meta:
        description = "Matches Mach-O file headers as uint32"
        last_modified = "2024-01-03"
        author = "@petermstewart"
        DaysofYara = "3/100"

    condition:
        uint32(0) == 0xfeedface or  //MH_MAGIC
        uint32(0) == 0xcefaedfe or  //MH_CIGAM
        uint32(0) == 0xfeedfacf or  //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or  //MH_CIGAM_64
        uint32(0) == 0xcafebabe or  //FAT_MAGIC
        uint32(0) == 0xbebafeca     //FAT_CIGAM
}

rule file_pe_signed {
    meta:
        description = "Finds signed Windows executables"
        last_modified = "2024-01-04"
        author = "@petermstewart"
        DaysofYara = "4/100"
        
    condition:
        uint16(0) == 0x5a4d and
        pe.number_of_signatures >= 1
}

rule file_zip {
    meta:
        description = "Finds files that look like ZIP archives"
        last_modified = "2024-02-12"
        author = "@petermstewart"
        DaysofYara = "43/100"
        ref = "https://en.wikipedia.org/wiki/ZIP_(file_format)"

    strings:
        $local_file_header = { 50 4b 03 04 }
        $central_directory_header = { 50 4b 01 02 }
        $end_of_central_directory = { 50 4b 05 06 }
        
    condition:
        $local_file_header at 0 and
        $central_directory_header and
        $end_of_central_directory
}

rule file_zip_password_protected {
    meta:
        description = "Finds files that look like password-protected ZIP archives"
        last_modified = "2024-02-13"
        author = "@petermstewart"
        DaysofYara = "44/100"
        ref = "https://en.wikipedia.org/wiki/ZIP_(file_format)"
        ref = "https://twitter.com/tylabs/status/1366728540683599878"

    strings:
        $local_file_header = { 50 4b 03 04 }
        $central_directory_header = { 50 4b 01 02 }
        $end_of_central_directory = { 50 4b 05 06 }
        
    condition:
        $local_file_header at 0 and
        uint16(6) & 0x1 == 0x1 and //Check the general purpose bit flag in the local file header
        $central_directory_header and
        $end_of_central_directory
}

rule file_msi {
    meta:
        description = "Finds Microsoft Installer (.msi) files"
        last_modified = "2024-03-02"
        author = "@petermstewart"
        DaysofYara = "62/100"

    strings:
        $magic = { d0 cf 11 e0 a1 b1 1a e1 }
        $clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        
    condition:
        $magic at 0 and
        $clsid
}

rule file_pdf_header {
    meta:
        description = "Finds Portable Document Format (.pdf) files"
        last_modified = "2024-03-06"
        author = "@petermstewart"
        DaysofYara = "66/100"
        ref = "https://en.wikipedia.org/wiki/PDF"

    condition:
        uint32(0) == 0x46445025
}
rule HUNT_Mimikatz_ascii_art {
	meta:
		description = "Matches ascii art Mimikatz logo."
		last_modified = "2024-03-05"
		author = "@petermstewart"
		DaysofYara = "65/100"
		sha256 = "912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9"

	strings:
		$a1 = ".#####." ascii wide
		$a2 = ".## ^ ##."  ascii wide
		$a3 = "## / \\ ##" ascii wide
		$a4 = "## \\ / ##" ascii wide
		$a5 = "'## v ##'" ascii wide
		$a6 = "'#####'" ascii wide

	condition:
		all of them
}

rule HUNT_GAZPROM_ascii_art {
	meta:
		description = "Matches ascii art found in GAZPROM ransomware samples."
		last_modified = "2024-03-12"
		author = "@petermstewart"
		DaysofYara = "72/100"
		sha256 = "5d61fcaa5ca55575eb82df8b87ab8d0a1d08676fd2085d4b7c91f4b16898d2f1"

	strings:
		$a1 = "⠄⠄⠄⠄⠄⠄⢀⣤⣴⣶⡶⠖⠂⠉⠓⠶⣦⣄⠄⠄⠄⠄⠄⠄"
		$a2 = "⠄⠄⠄⠄⢀⣼⣿⣿⡿⠋⠈⠄⠄⠄⠄⠄⠈⠛⠷⣦⡀⠄⠄⠄"
		$a3 = "⠄⠄⠄⣴⣿⣿⠟⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢻⣆⠄⠄"
		$a4 = "⠄⠄⢸⣿⣿⠇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⡄⠄"
		$a5 = "⠄⠄⣾⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⠄"
		$a6 = "⠄⠄⣿⣿⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⠄"
		$a7 = "⢠⣶⣿⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣀⠄⠄⢸⡇"
		$a8 = "⠈⠟⣻⣿⡇⠄⠄⠠⣤⣴⣿⣿⣿⣷⡆⠄⣰⣿⣟⣛⣿⠆⢸⠃"
		$a9 = "⠄⠄⠘⣫⢳⡀⠄⠄⠄⠉⠈⠋⠉⠉⠑⠄⠉⠁⠉⠁⠁⠄⠘⠄"
		$a10 = "⠄⠄⠄⠪⣼⣷⣄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⡆⠄"
		$a11 = "⠄⠄⠄⠐⢻⣿⢿⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⠁⠄"
		$a12 = "⠄⠄⠄⠄⠄⣿⡏⢣⠄⠄⠄⠄⠄⠑⢶⣤⣤⠂⠄⠄⠄⡼⠄⠄"
		$a13 = "⠄⠄⠄⠄⠄⢸⣷⣄⠄⠄⠄⢀⣄⣀⣀⠉⢀⣀⡄⠄⢠⠇⠄⠄"
		$a14 = "⠄⠄⠄⢀⣴⠈⣿⣿⣦⡀⠄⠈⠱⣧⣭⣭⣭⠟⠁⢀⣼⣧⡀⠄"
		$a15 = "⣶⣶⣶⣿⡟⠄⠙⢿⣿⣿⣦⣄⡀⠄⠄⠄⠄⢀⠴⠋⣼⣿⣿⣷"
		$a16 = "⣿⣿⣿⣿⠇⠄⠄⠄⠙⢿⣿⣿⣿⣿⡿⠟⠋⠁⠄⠄⣿⣿⣿⣿"
		$a17 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
		$a18 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
		$a19 = "⣿⣿⣿⠄⠄⠈⠄⠄⠄⣿⣿⣿⠋⠄⠄⠄⠄⠄⢸⣿⣿⣿⣿⣿"
		$a20 = "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"

	condition:
		all of them
}

rule HUNT_HuntersInternational_ascii_art {
	meta:
		description = "Matches ascii art found in Hunters International ransomware notes."
		last_modified = "2024-03-31"
		author = "@petermstewart"
		DaysofYara = "91/100"

	strings:
        $a1 = "_   _ _   _ _   _ _____ _____ ____  ____"
        $a2 = "| | | | | | | \\ | |_   _| ____|  _ \\/ ___|"
        $a3 = "| |_| | | | |  \\| | | | |  _| | |_) \\___ \\"
        $a4 = "|  _  | |_| | |\\  | | | | |___|  _ < ___) |"
        $a5 = "|_|_|_|\\___/|_|_\\_|_|_|_|_____|_|_\\_\\____/____ ___ ___  _   _    _    _"
        $a6 = "|_ _| \\ | |_   _| ____|  _ \\| \\ | |  / \\|_   _|_ _/ _ \\| \\ | |  / \\  | |"
        $a7 = "| ||  \\| | | | |  _| | |_) |  \\| | / _ \\ | |  | | | | |  \\| | / _ \\ | |"
        $a8 = "| || |\\  | | | | |___|  _ <| |\\  |/ ___ \\| |  | | |_| | |\\  |/ ___ \\| |___"
        $a9 = "|___|_| \\_| |_| |_____|_| \\_\\_| \\_/_/   \\_\\_| |___\\___/|_| \\_/_/   \\_\\_____|"

	condition:
		all of them
}
rule HUNT_nopsled_8 {
	meta:
		description = "Matches 8 repeated no-operation hex bytes - 0x90"
		last_modified = "2024-02-18"
		author = "@petermstewart"
		DaysofYara = "49/100"

	strings:
		$a = { 90 90 90 90 90 90 90 90 }

	condition:
		filesize < 5MB and
		$a
}

rule HUNT_nopsled_16 {
	meta:
		description = "Matches 16 repeated no-operation hex bytes - 0x90"
		last_modified = "2024-02-18"
		author = "@petermstewart"
		DaysofYara = "49/100"

	strings:
		$a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		filesize < 5MB and
		$a
}

rule HUNT_nopsled_32 {
	meta:
		description = "Matches 32 repeated no-operation hex bytes - 0x90"
		last_modified = "2024-02-18"
		author = "@petermstewart"
		DaysofYara = "49/100"

	strings:
		$a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		filesize < 5MB and
		$a
}
rule HUNT_PDF_contains_TLP_marking {
    meta:
        description = "Finds PDF files which contain TLP marking strings."
        last_modified = "2024-03-07"
        author = "@petermstewart"
        DaysofYara = "67/100"
        ref = "https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage"

    strings:
        $a = "TLP:RED" ascii wide fullword
        $b = "TLP:AMBER+STRICT" ascii wide fullword
        $c = "TLP:AMBER" ascii wide fullword
        $d = "TLP:GREEN" ascii wide fullword
        $e = "TLP:CLEAR" ascii wide fullword

    condition:
        uint32(0) == 0x46445025 and
        any of them
}
rule HUNT_Ransomware_generic_strings {
	meta:
		description = "Matches ransom note strings often found in ransomware binaries."
		last_modified = "2024-01-27"
		author = "@petermstewart"
		DaysofYara = "27/100"

	strings:
		$a1 = "Install TOR Browser" nocase ascii wide
		$a2 = "Download Tor" nocase ascii wide
		$a3 = "decrypt your files" nocase ascii wide
		$a4 = "your company is fully" nocase ascii wide
		$a5 = "recover your files" nocase ascii wide
		$a6 = "files were encrypted" nocase ascii wide
		$a7 = "files will be decrypted" nocase ascii wide
		$a8 = "Contact us" nocase ascii wide
		$a9 = "decrypt 1 file" nocase ascii wide
		$a10 = "has been encrypted" nocase ascii wide
		$a11 = "Contact information" nocase ascii wide
		$a12 = "pay the ransom" nocase ascii wide
		$a13 = "Decryption ID" nocase ascii wide
		$a14 = "are encrypted" nocase ascii wide

	condition:
		(uint16(0) == 0x5a4d or			//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		2 of them
}
rule HUNT_Royal_RSA_Public_Key {
	meta:
		description = "Matches an RSA Public Key block found in Royal ransomware Linux samples."
		last_modified = "2024-01-20"
		author = "@petermstewart"
		DaysofYara = "20/100"
		sha256 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"
		sha256 = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"

	strings:
		$key1 = "-----BEGIN RSA PUBLIC KEY-----"
		$key2 = "MIICCAKCAgEAp/24TNvKoZ9rzwMaH9kVGq4x1j+L/tgWH5ncB1TQA6eT5NDtgsQH"
		$key3 = "jv+6N3IY8P4SPSnG5QUBp9uYm3berObDuLURZ4wGW+HEKY+jNht5JD4aE+SS2Gjl"
		$key4 = "+lht2N+S8lRDAjcYXJZaCePN4pHDWQ65cVHnonyo5FfjKkQpDlzbAZ8/wBY+5gE4"
		$key5 = "Tex2Fdh7pvs7ek8+cnzkSi19xC0plj4zoMZBwFQST9iLK7KbRTKnaF1ZAHnDKaTQ"
		$key6 = "uCkJkcdhpQnaDyuUojb2k+gD3n+k/oN33Il9hfO4s67gyiIBH03qG3CYBJ0XfEWU"
		$key7 = "cvvahe+nZ3D0ffV/7LN6FO588RBlI2ZH+pMsyUWobI3TdjkdoHvMgJItrqrCK7BZ"
		$key8 = "TIKcZ0Rub+RQJsNowXbC+CbgDl38nESpKimPztcd6rzY32Jo7IcvAqPSckRuaghB"
		$key9 = "rkci/d377b6IT+vOWpNciS87dUQ0lUOmtsI2LLSkwyxauG5Y1W/MDUYZEuhHYlZM"
		$key10 = "cKqlSLmu8OTitL6bYOEQSy31PtCg2BOtlSu0NzW4pEXvg2hQyuSEbeWEGkrJrjTK"
		$key11 = "v9K7eu+eT5/arOy/onM56fFZSXfVseuC48R9TWktgCpPMkszLmwY14rp1ds6S7OO"
		$key12 = "/HLRayEWjwa0eR0r/GhEHX80C8IU54ksEuf3uHbpq8jFnN1A+U239q0CAQM="
		$key13 = "-----END RSA PUBLIC KEY-----"

	condition:
		filesize > 2MB and filesize < 3MB and
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		all of ($key*)
}
rule HUNT_Signal_Desktop_File_References {
	meta:
		description = "Contains references to sensitive database and key files used by Signal desktop application."
		last_modified = "2024-01-28"
		author = "@petermstewart"
		DaysofYara = "28/100"
		ref = "https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/"
		ref = "https://www.bleepingcomputer.com/news/security/signal-desktop-leaves-message-decryption-key-in-plain-sight/"

	strings:
		$win_db = "\\AppData\\Roaming\\Signal\\sql\\db.sqlite" nocase ascii wide
		$win_key = "\\AppData\\Roaming\\Signal\\config.json" nocase ascii wide
		$lin_db = "config/Signal/sql/db.sqlite" nocase ascii wide
		$lin_key = "config/Signal/config.json" nocase ascii wide
		$macos_db = "/Signal/sql/db.sqlite" nocase ascii wide
		$macos_key = "/Signal/config.json" nocase ascii wide

	condition:
		(uint16(0) == 0x5a4d or			//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		2 of them
}
rule HUNT_StripedFly {
	meta:
		description = "Matches strings found in Kaspersky Labs analysis of StripedFly malware."
		last_modified = "2024-02-15"
		author = "@petermstewart"
		DaysofYara = "46/100"
		ref = "https://securelist.com/stripedfly-perennially-flying-under-the-radar/110903/"

	strings:
		$a1 = "gpiekd65jgshwp2p53igifv43aug2adacdebmuuri34hduvijr5pfjad.onion" ascii wide
		$a2 = "ghtyqipha6mcwxiz.onion" ascii wide
		$a3 = "ajiumbl2p2mjzx3l.onion" ascii wide
		$b1 = "HKCU\\Software\\Classes\\TypeLib" ascii wide
		$b2 = "uname -nmo" ascii wide
		$b3 = "%s; chmod +x %s; nohup sh -c \"%s; rm %s\" &>/dev/null" ascii wide
		$b4 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" ascii wide

	condition:
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		1 of ($a*) and
		1 of ($b*)
}
rule MAL_APT_SugarGhost_Loader_strings {
	meta:
		description = "Matches strings found in the DLL loader component of SugarGhost malware."
		last_modified = "2024-03-24"
		author = "@petermstewart"
		DaysofYara = "84/100"
		sha256 = "34cba6f784c8b68ec9e598381cd3acd11713a8cf7d3deba39823a1e77da586b3"
		ref = "https://blog.talosintelligence.com/new-sugargh0st-rat/"

	strings:
		$a1 = "The ordinal %u could not be located in the dynamic link library %s"
		$a2 = "File corrupted!. This program has been manipulated and maybe"
		$a3 = "it's infected by a Virus or cracked. This file won't work anymore."

	condition:
		filesize > 200MB and
		uint16(0) == 0x5a4d and
		all of them
}
import "pe"

rule MAL_SQLMaggie_strings {
	meta:
		description = "Matches strings found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
		last_modified = "2024-01-06"
    		author = "@petermstewart"
    		DaysofYara = "6/100"
		ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
		sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"
	
	strings:
		$a1 = "Account Owner Not Found For The SID"
		$a2 = "%s Isn't Successfully Hooked Yet"
		$a3 = "About To Execute: %s %s %s"
		$a4 = "RunAs User Password Command"
		$a5 = "Wait 5 To 10 Seconds For TS Taking Effect"
		$a6 = "Re-Install TS Successfullly"
		$a7 = "ImpersonateLoggedOnUser = %d"
		$a8 = "The Account %s Has Been Cloned To %s"
		$a9 = "Fileaccess ObjectName [TrusteeName] [Permission] Options"
		$a10 = "SQL Scan Already Running"
		$a11 = "HellFire2050"

	condition:
		uint16(0) == 0x5a4d and
		8 of them
}

rule MAL_SQLMaggie_dll_export {
	meta:
		description = "Matches DLL export found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
		last_modified = "2024-01-07"
        	author = "@petermstewart"
        	DaysofYara = "7/100"
		ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
		sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"

	condition:
		uint16(0) == 0x5a4d and
		pe.number_of_exports == 1 and
		pe.export_details[0].name == "maggie"
}
rule MAL_SystemBC_Win_strings {
	meta:
		description = "Matches strings found in SystemBC malware Windows samples."
		last_modified = "2024-02-29"
		author = "@petermstewart"
		DaysofYara = "60/100"
		sha256 = "876c2b332d0534704447ab5f04d0eb20ff1c150fd60993ec70812c2c2cad3e6a"
		sha256 = "b9d6bf45d5a7fefc79dd567d836474167d97988fc77179a2c7a57f29944550ba"

	strings:
		$a1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
		$a2 = "GET %s HTTP/1.0"
		$a3 = "Host: %s"
		$a4 = "Connection: close"
		$b1 = "BEGINDATA"
		$b2 = "HOST1:"
		$b3 = "HOST2:"
		$b4 = "PORT1:"
		$b5 = "DNS:"
		$b6 = "-WindowStyle Hidden -ep bypass -file"

	condition:
		uint16(0) == 0x5a4d and
		all of ($a*) or
		5 of ($b*)
}

rule MAL_SystemBC_Lin_strings {
	meta:
		description = "Matches strings found in SystemBC malware Linux samples."
		last_modified = "2024-03-01"
		author = "@petermstewart"
		DaysofYara = "61/100"
		sha256 = "cf831d33e7ccbbdc4ec5efca43e28c6a6a274348bb7bac5adcfee6e448a512d9"
		sha256 = "b68bfd96f2690058414aaeb7d418f376afe5ba65d18ee4441398807b06d520fd"

	strings:
		$a1 = "Rc4_crypt" fullword
		$a2 = "newConnection" fullword
		$a3 = "/tmp/socks5.sh" fullword
		$a4 = "cat <(echo '@reboot echo" fullword
		$a5 = "socks5_backconnect" fullword

	condition:
		uint32(0) == 0x464c457f and
		2 of them
}
rule MAL_AsyncRAT_strings {
	meta:
		description = "Matches strings found in AsyncRAT samples."
		last_modified = "2024-02-22"
		author = "@petermstewart"
		DaysofYara = "53/100"
		sha256 = "00cdee79a9afc1bf239675ba0dc1850da9e4bf9a994bb61d0ec22c9fdd3aa36f"
		sha256 = "774e4d4af9175367bc3c7e08f4765778c58f1c66b46df88484a6aa829726f570"

	strings:
		$a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide
		$a2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
		$a3 = "bat.exe" wide
		$a4 = "Stub.exe" wide

	condition:
		uint16(0) == 0x5a4d and
		all of them
}

rule MAL_AsyncRAT_Github_release {
	meta:
		description = "Matches strings found in AsyncRAT Github release."
		last_modified = "2024-02-23"
		author = "@petermstewart"
		DaysofYara = "54/100"
		sha256 = "06899071233d61009a64c726a4523aa13d81c2517a0486cc99ac5931837008e5"
		ref = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        
	strings:
		$a1 = "NYAN-x-CAT"
		$a2 = "This program is distributed for educational purposes only."
		$a3 = "namespace AsyncRAT"
		$b1 = "[!] If you wish to upgrade to new version of AsyncRAT, You will need to copy 'ServerCertificate.p12'." wide
		$b2 = "[!] If you lose\\delete 'ServerCertificate.p12' certificate you will NOT be able to control your clients, You will lose them all." wide
		$b3 = "AsyncRAT | Dot Net Editor" wide
		$b4 = "XMR Miner | AsyncRAT" wide
		$b5 = "SEND A NOTIFICATION WHEN CLIENT OPEN A SPECIFIC WINDOW" wide
		$b6 = "Popup UAC prompt?" wide
		$b7 = "AsyncRAT | Unistall" wide
		$b8 = "recovered passwords successfully @ ClientsFolder" wide
	
	condition:
		uint16(0) == 0x5a4d and
		all of ($a*) or
		6 of ($b*)
}
rule MAL_BRC4_string_obfuscation_bytes {
	meta:
		description = "Matches hex byte pattern used to obfuscate strings in Brute Ratel (BRC4) samples."
		last_modified = "2024-02-03"
		author = "@petermstewart"
		DaysofYara = "34/100"
		sha256 = "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe"
		sha256 = "973f573cab683636d9a70b8891263f59e2f02201ffb4dd2e9d7ecbb1521da03e"

	strings:
		$a1 = { 50 48 B8 74 00 20 00 64 00 6F 00 50 48 } //PH,t. .d.o.PH
		$a2 = { 50 48 B8 6E 00 73 00 68 00 6F 00 50 48 } //PH,n.s.h.o.PH
		$a3 = { 50 48 B8 63 00 72 00 65 00 65 00 50 48 } //PH,c.r.e.e.PH
		$b1 = { 50 48 B8 69 00 6D 00 61 00 67 00 50 48 } //PH,i.m.a.g.PH
		$b2 = { 50 48 B8 32 64 2E 70 6E 67 00 00 50 48 } //PH,2d.png..PH
		$c1 = { 50 48 B8 6E 00 67 00 3A 00 20 00 50 48 } //PH,n.g.:. .PH
		$c2 = { 50 48 B8 65 00 72 00 79 00 69 00 50 48 } //PH,e.r.y.i.PH
		$c3 = { 50 48 B8 5D 00 20 00 51 00 75 00 50 48 } //PH,]. .Q.u.PH

	condition:
		uint16(0) == 0x5a4d and
		5 of them
}
rule MAL_CobaltStrike_Powershell_loader {
    meta:
        description = "Matches strings found in CobaltStrike PowerShell loader samples."
        last_modified = "2024-02-09"
        author = "@petermstewart"
        DaysofYara = "40/100"
        sha256 = "9c9e8841d706406bc23d05589f77eec6f8df6d5e4076bc6a762fdb423bfe8c24"
        sha256 = "6881531ab756d62bdb0c3279040a5cbe92f9adfeccb201cca85b7d3cff7158d3"
        ref = "https://medium.com/@cybenfolland/deobfuscating-a-powershell-cobalt-strike-beacon-loader-c650df862c34"
        ref = "https://forensicitguy.github.io/inspecting-powershell-cobalt-strike-beacon/"

    strings:
        $a1 = "=New-Object IO.MemoryStream("
        $a2 = "[Convert]::FromBase64String("
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        $b1 = "Set-StrictMode -Version 2"
        $b2 = "$DoIt = @'"
        $b3 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($DoIt))"
        $b4 = "start-job { param($a) IEX $a }"

    condition:
        all of ($a*) or
        all of ($b*)
}

rule MAL_CobaltStrike_Powershell_loader_base64 {
    meta:
        description = "Matches base64-encoded strings found in CobaltStrike PowerShell loader commands."
        last_modified = "2024-02-10"
        author = "@petermstewart"
        DaysofYara = "41/100"

    strings:
        $a1 = "=New-Object IO.MemoryStream(" base64 wide
        $a2 = "[Convert]::FromBase64String(" base64 wide
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()" base64 wide

    condition:
        all of them
}

rule MAL_CobaltStrike_HTA_loader {
    meta:
        description = "Matches strings found in CobaltStrike HTA loader samples."
        last_modified = "2024-02-11"
        author = "@petermstewart"
        DaysofYara = "42/100"
        sha256 = "2c683d112d528b63dfaa7ee0140eebc4960fe4fad6292c9456f2fbb4d2364680"
        ref = "https://embee-research.ghost.io/malware-analysis-decoding-a-simple-hta-loader/"

    strings:
        $header = "<script>"
        $a1 = "%windir%\\\\System32\\\\"
        $a2 = "/c powershell -w 1 -C"
        $b1 = "-namespace Win32Functions" base64 wide
        $b2 = "[Byte[]];[Byte[]]$" base64 wide
        $b3 = "{Start-Sleep 60};" base64 wide
        $b4 = "[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(" base64 wide
        $b5 = "\\syswow64\\WindowsPowerShell\\v1.0\\powershell\";iex" base64 wide
        $b6 = "else{;iex \"& powershell" base64 wide

    condition:
        $header at 0 and
        all of them
}
rule MAL_DarkComet_strings {
	meta:
		description = "Matches strings found in DarkComet malware samples."
		last_modified = "2024-02-28"
		author = "@petermstewart"
		DaysofYara = "59/100"
		sha256 = "3e10c254d6536cc63d286b53abfebbf53785e6509ae9fb569920747d379936f6"

	strings:
		$a1 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!"
		$a2 = "BTRESULTPing|Respond [OK] for the ping !|"
		$a3 = "BTRESULTClose Server|close command receive, bye bye...|"
		$a4 = "BTRESULTHTTP Flood|Http Flood task finished!|"
		$a5 = "BTRESULTMass Download|Downloading File...|"
		$a6 = "ERR|Cannot listen to port, try another one..|"

	condition:
		uint16(0) == 0x5a4d and
		all of them
}
rule MAL_Mythic_Apollo_strings {
    meta:
        description = "Matches strings found in samples of the Windows Apollo agent used by the open-source Mythic framework."
        last_modified = "2024-02-06"
        author = "@petermstewart"
        DaysofYara = "37/100"
        sha256 = "bf3d47335b7c10f655987cfdefecdb2856c0ac90f2f1cedcd67067760a80aa98"
        sha256 = "67b2c1c5d96a7c70b2bc111ace08b35e0db63bef40534dc50a692d46f832d61a"
        ref = "https://github.com/MythicAgents/apollo"

    strings:
        $pdb = "Apollo.pdb"
        $a = "ApolloInterop"
        $b1 = "ApolloTrackerUUID"
        $b2 = "Apollo.Peers.SMB"
        $b3 = "Apollo.Peers.TCP"
        $b4 = "C2ProfileData"
        $b5 = "mythicFileId"
        $b6 = "IMythicMessage"
        $b7 = ".MythicStructs"
        $b8 = ".ApolloStructs"
        $b9 = "Apollo.Api"
        $b10 = "ApolloLogonInformation"

    condition:
        uint16(0) == 0x5a4d and
        ($pdb and #a > 15) or
        ($a and (6 of ($b*)))
}

rule MAL_Mythic_Apfell_strings {
    meta:
        description = "Matches strings found in samples of the macOS Apfell Javascript agent used by the open-source Mythic framework."
        last_modified = "2024-02-07"
        author = "@petermstewart"
        DaysofYara = "38/100"
        sha256 = "8962ad7c608962c637637b9d3aef101a87cfb71873210046d5a49cfa6f47a712"
        ref = "https://github.com/MythicAgents/apfell"

    strings:
        $a1 = "C2.checkin(ip,apfell.pid,apfell.user,ObjC.unwrap(apfell.procInfo.hostName),apfell.osVersion,"
        $a2 = "return this.interval + (this.interval * (this.get_random_int(this.jitter)/100));"
        $a3 = "let info = {'ip':ip,'pid':pid,'user':user,'host':host,'uuid':apfell.uuid, \"os\":os, \"architecture\": arch, \"domain\": domain, \"action\": \"checkin\"};"
        $b1 = "\"user\": apfell.user,"
        $b2 = "\"fullName\": apfell.fullName,"
        $b3 = "\"ips\": apfell.ip,"
        $b4 = "\"hosts\": apfell.host,"
        $b5 = "\"environment\": apfell.environment,"
        $b6 = "\"uptime\": apfell.uptime,"
        $b7 = "\"args\": apfell.args,"
        $b8 = "\"pid\": apfell.pid,"
        $b9 = "\"apfell_id\": apfell.id,"
        $b10 = "\"payload_id\": apfell.uuid"
        $c1 = "-IMPLANT INFORMATION-"
        $c2 = "-Base C2 INFORMATION-"
        $c3 = "-RESTFUL C2 mechanisms -"
        $c4 = "- INSTANTIATE OUR C2 CLASS BELOW HERE IN MAIN CODE-"
        $c5 = "-SHARED COMMAND CODE -"
        $c6 = "-GET IP AND CHECKIN -"
        $c7 = "-MAIN LOOP -"
        $c8 = "//To create your own C2, extend this class and implement the required functions"
        $c9 = "//gets a file from the apfell server in some way"
        $c10 = "//there is a 3rd slash, so we need to splice in the port"
        $c11 = "//generate a time that's this.interval += (this.interval * 1/this.jitter)"
        $c12 = "// now we need to prepend the IV to the encrypted data before we base64 encode and return it"
        $c13 = "// Encrypt our initial message with sessionID and Public key with the initial AES key"
        $c14 = "//depending on the amount of data we're sending, we might need to chunk it"
        $c15 = "//if we do need to decrypt the response though, do that"
        $c16 = "// don't spin out crazy if the connection fails"
        $c17 = "// always round up to account for chunks that are < chunksize;"
        $c18 = "//simply run a shell command via doShellScript and return the response"
        $c19 = "//  so I'll just automatically fix this so it's not weird for the operator"
        $c20 = "//  params should be {\"cmds\": \"cmd1 cmd2 cmd3\", \"file_id\": #}"

    condition:
        (all of ($a*) and 8 of ($b*)) or
        (15 of ($c*))
}

rule MAL_Mythic_Athena_strings {
    meta:
        description = "Matches strings found in samples of the Athena agent used by the open-source Mythic framework."
        last_modified = "2024-02-08"
        author = "@petermstewart"
        DaysofYara = "39/100"
        sha256 = "8075738035ac361d50db2c2112a539acc3f1ad4d4ed5f971b2e18c687fc029da"
        sha256 = "ce66c7487e56722f34e5fd0fea167f9c562a0bbb0d13128b0313e4d3eabff697"
        ref = "https://github.com/MythicAgents/athena"

    strings:
        $a = "Athena"
        $b1 = "\"Athena.Commands\":"
        $b2 = "\"Athena.Forwarders.SMB\":"
        $c1 = "\"cat\":"
        $c2 = "\"drives\":"
        $c3 = "\"get-clipboard\":"
        $c4 = "\"get-localgroup\":"
        $c5 = "\"get-sessions\":"
        $c6 = "\"get-shares\":"
        $c7 = "\"hostname\":"
        $c8 = "\"ifconfig\":"
        $c9 = "\"ls\":"
        $c10 = "\"mkdir\":"
        $c11 = "\"mv\":"
        $c12 = "\"ps\":"
        $c13 = "\"pwd\":"
        $c14 = "\"rm\":"
        $c15 = "\"shell\":"
        $c16 = "\"shellcode\":"
        $c17 = "\"whoami\":"

    condition:
        uint16(0) == 0x5a4d and
        #a > 100 and
        all of ($b*) and
        8 of ($c*)
}
rule MAL_Netwire_strings {
	meta:
		description = "Matches strings found in NetWire malware samples."
		last_modified = "2024-02-27"
		author = "@petermstewart"
		DaysofYara = "58/100"
		sha256 = "05a36b671efa242764695140c004dfff3e0ff9d11df5d74005b7c1c8c53d8f00"
		sha256 = "d2a60c0cb4dd0c53c48bc062ca754d94df400dee9b672cf8881f5a1eff5b4fbe"

	strings:
		$ua = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
		$a1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
		$a2 = "Accept-Language: en-US,en;q=0.8"
		$a3 = "GET %s HTTP/1.1" 
		$b1 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1"
		$b2 = "DEL /s \"%s\" >nul 2>&1"
		$b3 = "call :deleteSelf&exit /b"
		$b4 = ":deleteSelf"
		$b5 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b"
		$b6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
		$c1 = "%6\\EWWnid\\PI0Wld\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c2 = "%6\\PI0Wl4Ql\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c3 = "%6\\PWlWSW\\a0CnWR\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c4 = "%6\\vCRSdf\\vCRSdfc0Wg6d0\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c5 = "%6\\Tsd0C MW85gC0d\\Tsd0C M5CVid\\mWn4R aC5C"

	condition:
		uint16(0) == 0x5a4d and
		12 of them
}
rule MAL_Nighthawk_bytes {
	meta:
		description = "Matches hex byte pattern referenced in Proofpoint blog reversing Nighthawk malware."
		last_modified = "2024-02-02"
		author = "@petermstewart"
		DaysofYara = "33/100"
		ref = "https://web.archive.org/web/20221122125826/https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		sha256 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		sha256 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"

	strings:
		//   { 48 8d 0d f9 ff ff ff 51 5a 48 81 c1 20 4e 00 00 48 81 c2 64 27 00 00 ff e2 }
		$a = { 48 8d 0d ?? ff ff ff ?? ?? ?? ?? ?? ?? ?? 00 00 }

	condition:
		filesize > 500KB and filesize < 1MB and
		uint16(0) == 0x5a4d and
		$a
}
rule MAL_Nimplant_strings {
    meta:
        description = "Matches strings found in open-source Nimplant samples."
        last_modified = "2024-02-05"
        author = "@petermstewart"
        DaysofYara = "36/100"
        sha256 = "4d7eb09c35a644118af702dd402fd9f5a75e490d33e86b6746e6eb6112c5caa7"
        sha256 = "90a5e330d411d84a09ef4af07d2b9c808acc028a91fa7e1d57c4f063e91fad49"
        ref = "https://github.com/chvancooten/NimPlant"

    strings:
        $ver = "NimPlant v"
        $header1 = "@Content-Type"
        $header2 = "@X-Identifier"
        $header3 = "@User-Agent"
        $cmd1 = "getLocalAdm"
        $cmd2 = "getAv"

    condition:
        uint16(0) == 0x5a4d and
        filesize > 300KB and filesize < 1MB and
        all of them
}
rule MAL_PingRAT_client_strings {
    meta:
        description = "Matches strings found in the PingRAT client binary and source code."
        last_modified = "2024-03-08"
        author = "@petermstewart"
        DaysofYara = "68/100"
        sha256 = "51bcb9d9b2e3d8292d0666df573e1a737cc565c0e317ba18cb57bd3164daa4bf"
        ref = "https://github.com/umutcamliyurt/PingRAT"

    strings:
        $a1 = "(Virtual) Network Interface (e.g., eth0)"
        $a2 = "Destination IP address"
        $a3 = "[+] ICMP listener started!"
        $b1 = "golang.org/x/net/icmp"
        $b2 = "golang.org/x/net/ipv4"
        $b3 = "os/exec"

    condition:
        all of them
}

rule MAL_PingRAT_server_strings {
    meta:
        description = "Matches strings found in the PingRAT server binary and source code."
        last_modified = "2024-03-09"
        author = "@petermstewart"
        DaysofYara = "69/100"
        sha256 = "81070ba18e6841ee7ec44b00bd33e8a44c8c1af553743eebcb0d44b47130b677"
        ref = "https://github.com/umutcamliyurt/PingRAT"

    strings:
        $a1 = "Listener (virtual) Network Interface (e.g. eth0)"
        $a2 = "Destination IP address"
        $a3 = "Please provide both interface and destination IP address."
        $a4 = "[+] ICMP C2 started!"
        $a5 = "[+] Command sent to the client:"
        $a6 = "[+] Stopping ICMP C2..."
        $b1 = "golang.org/x/net/icmp"
        $b2 = "golang.org/x/net/ipv4"
        $b3 = "os/signal"

    condition:
        all of them
}
rule MAL_Remcos_strings {
    meta:
        description = "Matches strings found in Remcos RAT samples."
        last_modified = "2024-03-20"
        author = "@petermstewart"
        DaysofYara = "80/100"
        sha256 = "b3d7fad59a0ae75ffef9e05f47fc381b4adb716c498106482492e56c1b4370a7"
        sha256 = "9046b2e6ce92647474048c30439ab21ee69a46f6067dbaff67de729644120fad"

    strings:
        $a = "Remcos_Mutex_Inj"
        $b1 = "Uploading file to C&C: "
        $b2 = "Unable to delete: "
        $b3 = "Unable to rename file!"
        $b4 = "Browsing directory: "
        $b5 = "Offline Keylogger Started"
        $b6 = "Online Keylogger Started"
        $b7 = "[Chrome StoredLogins found, cleared!]"
        $b8 = "[Firefox StoredLogins cleared!]"
        $b9 = "Cleared all browser cookies, logins and passwords."
        $b10 = "[Following text has been pasted from clipboard:]"
        $b11 = "[End of clipboard text]"
        $b12 = "OpenCamera"
        $b13 = "CloseCamera"

    condition:
        uint16(0) == 0x5a4d and
        $a and
        10 of ($b*)
}
rule MAL_Sliver_implant_strings {
	meta:
		description = "Matches strings found in open-source Sliver beacon samples."
		last_modified = "2024-02-04"
		author = "@petermstewart"
		DaysofYara = "35/100"
		sha256 = "6037eaaa80348d44a51950b45b98077b3aeb16c66a983a8cc360d079daaaf53e"
		sha256 = "98df535576faab0405a2eabcd1aac2c827a750d6d4c3d76a716c24353bedf0b5"
		sha256 = "789e5fcb242ee1fab8ed39e677d1bf26c7ce275ae38de5a63b4d902c58e512ec"

	strings:
		$a1 = "bishopfox/sliver"
		$a2 = "sliver/protobuf"
		$a3 = "protobuf/commonpbb"
		$b1 = "ActiveC2Fprotobuf:\"bytes,11,opt,name="
		$b2 = "ProxyURLFprotobuf:\"bytes,14,opt,name="
		$b3 = "BeaconJitterNprotobuf:\"varint,3,opt,name="
		$b4 = "BeaconIntervalRprotobuf:\"varint,2,opt,name="
		$b5 = "BeaconIDEprotobuf:\"bytes,8,opt,name="
		$b6 = "BeaconID"
		$b7 = "GetBeaconJitter"
		$b8 = "BeaconRegister"

	condition:
		(filesize > 5MB and filesize < 20MB) and
		(uint16(0) == 0x5a4d or			//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		2 of ($a*) or
		6 of ($b*)
}
rule MAL_BumbleBee_PowerShell_strings {
	meta:
		description = "Matches strings found in BumbleBee PowerShell loaders."
		last_modified = "2024-01-29"
		author = "@petermstewart"
		DaysofYara = "29/100"
		sha256 = "0ff8988d76fc6bd764a70a7a4f07a15b2b2c604138d9aadc784c9aeb6b77e275"
		sha256 = "9b6125e1aa889f2027111106ee406d08a21c894a83975b785a2b82aab3e2ac52"
		sha256 = "2102214c6a288819112b69005737bcfdf256730ac859e8c53c9697e3f87839f2"
		sha256 = "e9a1ce3417838013412f81425ef74a37608754586722e00cacb333ba88eb9aa7"

	strings:
		$a1 = "[System.Convert]::FromBase64String" ascii wide
		$a2 = "System.IO.Compression.GZipStream" ascii wide
		$elem = "$elem" ascii wide
		$invoke1 = ".Invoke(0,1)" ascii wide
		$invoke2 = ".Invoke(0,\"H\")" ascii wide

	condition:
		filesize > 1MB and filesize < 10MB and
		all of ($a*) and
		#elem > 30 and
		#invoke1 > 30 and
		#invoke2 > 30
}

rule MAL_BumbleBee_DLL_strings {
	meta:
		description = "Matches strings found in BumbleBee DLL sample extracted from initial PowerShell loader."
		last_modified = "2024-01-30"
		author = "@petermstewart"
		DaysofYara = "30/100"
		sha256 = "39e300a5b4278a3ff5fe48c7fa4bd248779b93bbb6ade55e38b22de5f9d64c3c"

	strings:
		$a1 = "powershell -ep bypass -Command"
		$a2 = " -Command \"Wait-Process -Id "
		$a3 = "schtasks.exe /F /create /sc minute /mo 4 /TN \""
		$a4 = "/ST 04:00 /TR \"wscript /nologo"
		$b1 = "SELECT * FROM Win32_ComputerSystemProduct"
		$b2 = "SELECT * FROM Win32_ComputerSystem"
		$b3 = "SELECT * FROM Win32_OperatingSystem"
		$b4 = "SELECT * FROM Win32_NetworkAdapterConfiguration" wide
		$b5 = "SELECT * FROM Win32_NTEventlogFile" wide
		$b6 = "SELECT * FROM Win32_PnPEntity" wide

	condition:
		uint16(0) == 0x5a4d and
		3 of ($a*) and
		4 of ($b*)
}
rule MAL_Loader_KrustyLoader_strings {
	meta:
		description = "Matches strings found in KrustyLoader malware samples."
		last_modified = "2024-03-25"
		author = "@petermstewart"
		DaysofYara = "85/100"
		sha256 = "030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0"
		ref = "https://www.synacktiv.com/en/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises"

	strings:
		$a1 = "|||||||||||||||||||||||||||||||||||"
		$a2 = "/proc/self/exe"
		$a3 = "/tmp/"
		$a4 = "TOKIO_WORKER_THREADS"

	condition:
		uint32(0) == 0x464c457f and
		all of them
}
rule MAL_PrivateLoader_strings {
	meta:
		description = "Matches strings found in PrivateLoader malware samples."
		last_modified = "2024-02-26"
		author = "@petermstewart"
		DaysofYara = "57/100"
		sha256 = "077225467638a420cf29fb9b3f0241416dcb9ed5d4ba32fdcf2bf28f095740bb"
		sha256 = "27c1ed01c767f504642801a7e7a7de8d87dbc87dee88fbc5f6adb99f069afde4"

	strings:
		$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" ascii wide
		$b1 = ".?AVBase@Rijndael@CryptoPP@@" ascii
		$b2 = ".?AVCannotFlush@CryptoPP@@" ascii
		$b3 = ".?AVBase64Decoder@CryptoPP@@" ascii
		$b4 = ".?AVCBC_Encryption@CryptoPP@@" ascii
		$b5 = "Cleaner" ascii
		$c1 = "Content-Type: application/x-www-form-urlencoded" wide
		$c2 = "https://ipinfo.io/" wide
		$c3 = "https://db-ip.com/" wide
		$c4 = "https://www.maxmind.com/en/locate-my-ip-address" wide
		$c5 = "https://ipgeolocation.io/" wide

	condition:
		uint16(0) == 0x5a4d and
		($ua and 4 of them) or
		all of ($b*) or
		all of ($c*)
}
rule MAL_LemonDuck_strings {
	meta:
		description = "Matches strings found in Lemonduck cryptominer samples."
		last_modified = "2024-01-31"
		author = "@petermstewart"
		DaysofYara = "31/100"
		sha256 = "a5de49d6b14b04ba854246e1945ea1cfc8a7e7e254d0974efaba6415922c756f"

	strings:
		$a1 = "stratum+tcp"
		$a2 = "stratum+ssl"
		$b1 = "\"donate-level\":"
		$b2 = "\"health-print-time\":"
		$b3 = "\"retry-pause\":"
		$b4 = "\"nicehash\":"
		$b5 = "\"coin\":"
		$b6 = "\"randomx\":"
		$b7 = "\"opencl\":"
		$b8 = "\"cuda\":"
		$b9 = "This is a test This is a test This is a test"

	condition:
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		1 of ($a*) and
		8 of ($b*)
}
rule MAL_XMRig_strings {
	meta:
		description = "Matches strings found in XMRig cryptominer samples."
		last_modified = "2024-02-14"
		author = "@petermstewart"
		DaysofYara = "45/100"
		sha256 = "3c54646213638e7bd8d0538c28e414824f5eaf31faf19a40eec608179b1074f1"

	strings:
		$a1 = "Usage: xmrig [OPTIONS]"
		$a2 = "mining algorithm https://xmrig.com/docs/algorithms"
		$a3 = "username:password pair for mining server"
		$a4 = "--rig-id=ID"
		$a5 = "control donate over xmrig-proxy feature"
		$a6 = "https://xmrig.com/benchmark/%s"
		$a7 = "\\xmrig\\.cache\\"
		$a8 = "XMRIG_INCLUDE_RANDOM_MATH"
		$a9 = "XMRIG_INCLUDE_PROGPOW_RANDOM_MATH"
		$a10 = "'h' hashrate, 'p' pause, 'r' resume, 's' results, 'c' connection"

	condition:
		7 of them
}
rule MAL_AbyssLocker_Lin_strings {
	meta:
		description = "Matches strings found in SentinelOne analysis of Linux variant of the Abyss Locker ransomware."
		last_modified = "2024-02-16"
		author = "@petermstewart"
		DaysofYara = "47/100"
		ref = "https://www.sentinelone.com/anthology/abyss-locker/"

	strings:
		$a1 = "Usage:%s [-m (5-10-20-25-33-50) -v -d] Start Path"
		$b1 = "esxcli vm process list"
		$b2 = "esxcli vm process kill -t=force -w=%d"
		$b3 = "esxcli vm process kill -t=hard -w=%d"
		$b4 = "esxcli vm process kill -t=soft -w=%d"
		$c1 = ".crypt" fullword
		$c2 = "README_TO_RESTORE"

	condition:
		uint32(0) == 0x464c457f and
		all of them
}

rule MAL_AbyssLocker_ransomnote {
	meta:
		description = "Matches strings found in SentinelOne analysis of Abyss Locker note."
		last_modified = "2024-02-17"
		author = "@petermstewart"
		DaysofYara = "48/100"
		ref = "https://www.sentinelone.com/anthology/abyss-locker/"

	strings:
		$a1 = "Your company Servers are locked and Data has been taken to our servers. This is serious."
		$a2 = "Good news:"
		$a3 = "100% of your Server system and Data will be restored by our Decryption Tool;"
		$a4 = "for now, your data is secured and safely stored on our server;"
		$a5 = "nobody in the world is aware about the data leak from your company except you and Abyss Locker team."
		$a6 = "Want to go to authorities for protection?"
		$a7 = "they will do their job properly, but you will not get any win points out of it, only headaches;"
		$a8 = "they will never make decryption for data or servers"
		$a9 = "Also, they will take all of your IT infrastructure as a part of their procedures"
		$a10 = "but still they will not help you at all."
		$a11 = "Think you can handle it without us by decrypting your servers and data using some IT Solution from third-party non-hackers"

	condition:
		filesize < 5KB and
		8 of them
}
rule MAL_Akira_strings {
	meta:
		description = "Matches strings found in Akira ransomware sample."
		last_modified = "2024-01-12"
                author = "@petermstewart"
                DaysofYara = "12/100"
                sha256 = "3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c"

	strings:
		$a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
		$a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
		$b = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
		$c1 = "This is local disk:" wide
		$c2 = "This is network disk:" wide
		$c3 = "This is network path:" wide
		$c4 = "Not allowed disk:" wide

	condition:
		filesize < 2MB and
		uint16(0) == 0x5a4d and
		1 of ($a*) and
		$b and
		2 of ($c*)
}

rule MAL_Akira_ransomnote {
	meta:
		description = "Matches strings found in Akira ransom note sample."
		last_modified = "2024-01-13"
		author = "@petermstewart"
		DaysofYara = "13/100"

	strings:
		$a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
		$a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
		$b1 = "Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead"
		$b2 = "all your backups - virtual, physical - everything that we managed to reach - are completely removed"
		$b3 = "Moreover, we have taken a great amount of your corporate data prior to encryption"
		$b4 = "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue"
		$b5 = "We're fully aware of what damage we caused by locking your internal sources"
		$b6 = "At the moment, you have to know"
		$b7 = "Dealing with us you will save A LOT due to we are not interested in ruining your financially"
		$b8 = "We will study in depth your finance, bank & income statements, your savings, investments etc. and present our reasonable demand to you"
		$b9 = "If you have an active cyber insurance, let us know and we will guide you how to properly use it"
		$b10 = "Also, dragging out the negotiation process will lead to failing of a deal"
		$b11 = "Paying us you save your TIME, MONEY, EFFORTS and be back on track within 24 hours approximately"
		$b12 = "Our decryptor works properly on any files or systems, so you will be able to check it by requesting a test decryption service from the beginning of our conversation"
		$b13 = "If you decide to recover on your own, keep in mind that you can permanently lose access to some files or accidently corrupt them - in this case we won't be able to help"
		$b14 = "The security report or the exclusive first-hand information that you will receive upon reaching an agreement is of a great value"
		$b15 = "since NO full audit of your network will show you the vulnerabilities that we've managed to detect and used in order to get into, identify backup solutions and upload your data"
		$b16 = "As for your data, if we fail to agree, we will try to sell personal information/trade secrets/databases/source codes"
		$b17 = "generally speaking, everything that has a value on the darkmarket - to multiple threat actors at ones"
		$b18 = "Then all of this will be published in our blog"
		$b19 = "We're more than negotiable and will definitely find the way to settle this quickly and reach an agreement which will satisfy both of us"
		$b20 = "If you're indeed interested in our assistance and the services we provide you can reach out to us following simple instructions"
		$b21 = "Install TOR Browser to get access to our chat room"
		$b22 = "Keep in mind that the faster you will get in touch, the less damage we cause"

	condition:
		filesize < 100KB and
		1 of ($a*) and
		18 of ($b*)
}
rule MAL_BlackCat_Win_strings {
	meta:
		description = "Matches strings found in BlackCat ransomware Windows samples operated by ALPHV."
		last_modified = "2024-01-14"
		author = "@petermstewart"
		DaysofYara = "14/100"
		sha256 = "2587001d6599f0ec03534ea823aab0febb75e83f657fadc3a662338cc08646b0"
		sha256 = "c3e5d4e62ae4eca2bfca22f8f3c8cbec12757f78107e91e85404611548e06e40"

	strings:
		$a = "bcdedit /set {default}bcdedit /set {default} recoveryenabled"
		$b = "vssadmin.exe Delete Shadows /all /quietshadow_copy::remove_all_vss="
		$c = "wmic.exe Shadowcopy Deleteshadow_copy::remove_all_wmic="
		$d = "deploy_note_and_image_for_all_users="
		$e = "Control Panel\\DesktopWallpaperStyleWallPaperC:\\\\Desktop\\.png"
		$f = "Speed:  Mb/s, Data: Mb/Mb, Files processed: /, Files scanned:"

	condition:
		filesize > 2MB and filesize < 4MB and
		uint16(0) == 0x5a4d and
		all of them
}

rule MAL_BlackCat_Lin_strings {
	meta:
		description = "Matches strings found in BlackCat ransomware Linux samples operated by ALPHV"
		last_modified = "2024-01-15"
		author = "@petermstewart"
		DaysofYara = "15/100"
		sha256 = "3a08e3bfec2db5dbece359ac9662e65361a8625a0122e68b56cd5ef3aedf8ce1"
		sha256 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"

	strings:
		$a1 = "encrypt_app::linux"
		$a2 = "src/bin/encrypt_app/linux.rs"
		$a3 = "locker::core::os::linux::command"
		$b1 = "note_file_name"
		$b2 = "note_full_text"
		$b3 = "note_short_text"
		$b4 = "default_file_cipher"
		$b5 = "default_file_mode"
		$b6 = "enable_esxi_vm_kill"
		$b7 = "enable_esxi_vm_snapshot_kill"

	condition:
		filesize > 1MB and filesize < 3MB and
		uint32(0) == 0x464c457f and
		2 of ($a*) and
		5 of ($b*)
}

rule MAL_BlackCat_ransomnote {
	meta:
		description = "Matches strings found in two versions of ransom notes dropped by BlackCat (ALPHV)."
		last_modified = "2024-01-16"
		author = "@petermstewart"
		DaysofYara = "16/100"

	strings:
		$heading1a = ">> What happened?"
		$heading1b = ">> Introduction"
		$heading2 = ">> Sensitive Data"
		$heading3 = ">> CAUTION"
		$heading4a = ">> What should I do next?"
		$heading4b = ">> Recovery procedure"
		$a1 = "In order to recover your files you need to follow instructions below."
		$a2 = "clients data, bills, budgets, annual reports, bank statements"
		$a3 = "1) Download and install Tor Browser from: https://torproject.org/"
		$a4 = "2) Navigate to: http://"

	condition:
		filesize < 5KB and
		($heading1a and $heading4a) or ($heading1b and $heading4b) and
		$heading2 and $heading3 and 
		all of ($a*)
}
rule MAL_BlackSuit_strings {
	meta:
		description = "Matches strings found in open-source reporting on BlackSuit Windows and Linux ransomware."
		last_modified = "2024-01-24"
		author = "@petermstewart"
		DaysofYara = "24/100"
		sha256 = "90ae0c693f6ffd6dc5bb2d5a5ef078629c3d77f874b2d2ebd9e109d8ca049f2c"
		sha256 = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
		ref = "https://twitter.com/siri_urz/status/1653692714750279681"
		ref = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
		ref = "https://www.trendmicro.com/en_us/research/23/e/investigating-blacksuit-ransomwares-similarities-to-royal.html"

	strings:
		$a = "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion"
		$b1 = "Good whatever time of day it is!"
		$b2 = "Your safety service did a really poor job of protecting your files against our professionals."
		$b3 = "Extortioner named  BlackSuit has attacked your system."
		$b4 = "As a result all your essential files were encrypted and saved at a secure server for further use and publishing on the Web into the public realm."
		$b5 = "Now we have all your files like: financial reports, intellectual property, accounting, law actionsand complaints, personal files and so on and so forth."
		$b6 = "We are able to solve this problem in one touch."
		$b7 = "We (BlackSuit) are ready to give you an opportunity to get all the things back if you agree to makea deal with us."
		$b8 = "You have a chance to get rid of all possible financial, legal, insurance and many others risks and problems for a quite small compensation."
		$b9 = "You can have a safety review of your systems."
		$b10 = "All your files will be decrypted, your data will be reset, your systems will stay in safe."
		$b11 = "Contact us through TOR browser using the link:"

	condition:
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		$a and
		8 of ($b*)
}

rule MAL_BlackSuit_ransomnote {
	meta:
		description = "Matches strings found in open-source reporting of BlackSuit ransom notes."
		last_modified = "2024-01-25"
		author = "@petermstewart"
		DaysofYara = "25/100"
		ref = "https://twitter.com/siri_urz/status/1653692714750279681"
		ref = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
		ref = "https://www.trendmicro.com/en_us/research/23/e/investigating-blacksuit-ransomwares-similarities-to-royal.html"

	strings:
		$a = "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion"
		$b1 = "Good whatever time of day it is!"
		$b2 = "Your safety service did a really poor job of protecting your files against our professionals."
		$b3 = "Extortioner named  BlackSuit has attacked your system."
		$b4 = "As a result all your essential files were encrypted and saved at a secure server for further use and publishing on the Web into the public realm."
		$b5 = "Now we have all your files like: financial reports, intellectual property, accounting, law actionsand complaints, personal files and so on and so forth."
		$b6 = "We are able to solve this problem in one touch."
		$b7 = "We (BlackSuit) are ready to give you an opportunity to get all the things back if you agree to makea deal with us."
		$b8 = "You have a chance to get rid of all possible financial, legal, insurance and many others risks and problems for a quite small compensation."
		$b9 = "You can have a safety review of your systems."
		$b10 = "All your files will be decrypted, your data will be reset, your systems will stay in safe."
		$b11 = "Contact us through TOR browser using the link:"

	condition:
		filesize < 5KB and
		$a and
		8 of ($b*)
}
rule MAL_Cactus_strings {
	meta:
		description = "Matches strings found in Cactus ransomware samples."
		last_modified = "2024-03-22"
		author = "@petermstewart"
		DaysofYara = "82/100"
		sha256 = "1ea49714b2ff515922e3b606da7a9f01732b207a877bcdd1908f733eb3c98af3"
		sha256 = "c49b4faa6ac7b5c207410ed1e86d0f21c00f47a78c531a0a736266c436cc1c0a"

	strings:
		$a1 = "vssadmin delete shadows /all /quiet" wide
		$a2 = "WMIC shadowcopy delete" wide
		$a3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide
		$a4 = "bcdedit /set {default} recoveryenabled no" wide
		$a5 = "cAcTuS" wide
		$a6 = "CaCtUs.ReAdMe.txt" wide
		$a7 = "schtasks.exe /create /sc MINUTE /mo 5 /rl HIGHEST /ru SYSTEM /tn \"Updates Check Task\" /tr \"cmd /c cd C:\\ProgramData &&" wide
		$a8 = "C:\\Windows\\system32\\schtasks.exe /run /tn \"Updates Check Task\"" wide

	condition:
		uint16(0) == 0x5a4d and
		6 of them
}

rule MAL_Cactus_ransomnote {
	meta:
		description = "Matches strings found in ransom notes dropped by Cactus ransomware."
		last_modified = "2024-03-23"
		author = "@petermstewart"
		DaysofYara = "83/100"
		
	strings:
		$a1 = "cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion"
		$a2 = "sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion"
		$a3 = "cactus2tg32vfzd6mwok23jfeolh4yxrg2obzlsyax2hfuka3passkid.onion"
		$b1 = "encrypted by Cactus"
		$b2 = "Do not interrupt the encryption process"
		$b3 = "Otherwise the data may be corrupted"
		$b4 = "wait until encryption is finished"
		$b6 = "TOX (https://tox.chat):"
		$b7 = "7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421AE1D49ACEABB2"

	condition:
		filesize < 5KB and
		1 of ($a*) or
		5 of ($b*)
}
rule MAL_ChaosRansom_strings {
    meta:
        description = "Matches function name strings found in Chaos ransomware samples."
        last_modified = "2024-03-19"
        author = "@petermstewart"
        DaysofYara = "79/100"
        sha256 = "1ba5ab55b7212ba92a9402677e30e45f12d98a98f78cdcf5864a67d6c264d053"
        sha256 = "a98bc2fcbe8b3c7ea9df3712599a958bae0b689ae29f33ee1848af7a038d518a"

    strings:
        $a1 = "encryptionAesRsa"
        $a2 = "encryptedFileExtension"
        $a3 = "checkdeleteShadowCopies"
        $a4 = "checkdisableRecoveryMode"
        $a5 = "bytesToBeEncrypted"

    condition:
        uint16(0) == 0x5a4d and
        4 of them
}
rule MAL_GAZPROM_strings {
	meta:
		description = "Matches strings found in Windows samples of GAZPROM ransomware."
		last_modified = "2024-03-11"
		author = "@petermstewart"
		DaysofYara = "71/100"
		sha256 = "5d61fcaa5ca55575eb82df8b87ab8d0a1d08676fd2085d4b7c91f4b16898d2f1"

	strings:
		$a = ".GAZPROM" wide
		$b1 = "Your files has been encrypted!"
		$b2 = "Need restore? Contact us:"
		$b3 = "Telegram @gazpromlock"
		$b4 = "Dont use any third party software for restoring your data!"
		$b5 = "Do not modify and rename encrypted files!"
		$b6 = "Decryption your files with the help of third parties may cause increased price."
		$b7 = "They add their fee to our and they usually fail or you can become a victim of a scam."
		$b8 = "We guarantee complete anonymity and can provide you with proof and"
		$b9 = "guaranties from our side and our best specialists make everything for restoring"
		$b10 = "but please should not interfere without us."
		$b11 = "If you dont contact us within 24 hours from encrypt your files - price will be higher."
		$b12 = "Your decrypt key:"

	condition:
		filesize > 200KB and filesize < 350KB and
		uint16(0) == 0x5a4d and
		$a and
		10 of ($b*)
}

rule MAL_GAZPROM_ransomnote {
	meta:
		description = "Matches strings found in GAZPROM ransomware samples."
		last_modified = "2024-03-12"
		author = "@petermstewart"
		DaysofYara = "72/100"

	strings:
		$a1 = "⠄⠄⠄⠄⠄⠄⢀⣤⣴⣶⡶⠖⠂⠉⠓⠶⣦⣄⠄⠄⠄⠄⠄⠄"
		$a2 = "⠄⠄⠄⠄⢀⣼⣿⣿⡿⠋⠈⠄⠄⠄⠄⠄⠈⠛⠷⣦⡀⠄⠄⠄"
		$a3 = "⠄⠄⠄⣴⣿⣿⠟⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢻⣆⠄⠄"
		$a4 = "⠄⠄⢸⣿⣿⠇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⡄⠄"
		$a5 = "⠄⠄⣾⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⠄"
		$a6 = "⠄⠄⣿⣿⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⠄"
		$a7 = "⢠⣶⣿⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣀⠄⠄⢸⡇"
		$a8 = "⠈⠟⣻⣿⡇⠄⠄⠠⣤⣴⣿⣿⣿⣷⡆⠄⣰⣿⣟⣛⣿⠆⢸⠃"
		$a9 = "⠄⠄⠘⣫⢳⡀⠄⠄⠄⠉⠈⠋⠉⠉⠑⠄⠉⠁⠉⠁⠁⠄⠘⠄"
		$a10 = "⠄⠄⠄⠪⣼⣷⣄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⡆⠄"
		$a11 = "⠄⠄⠄⠐⢻⣿⢿⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⠁⠄"
		$a12 = "⠄⠄⠄⠄⠄⣿⡏⢣⠄⠄⠄⠄⠄⠑⢶⣤⣤⠂⠄⠄⠄⡼⠄⠄"
		$a13 = "⠄⠄⠄⠄⠄⢸⣷⣄⠄⠄⠄⢀⣄⣀⣀⠉⢀⣀⡄⠄⢠⠇⠄⠄"
		$a14 = "⠄⠄⠄⢀⣴⠈⣿⣿⣦⡀⠄⠈⠱⣧⣭⣭⣭⠟⠁⢀⣼⣧⡀⠄"
		$a15 = "⣶⣶⣶⣿⡟⠄⠙⢿⣿⣿⣦⣄⡀⠄⠄⠄⠄⢀⠴⠋⣼⣿⣿⣷"
		$a16 = "⣿⣿⣿⣿⠇⠄⠄⠄⠙⢿⣿⣿⣿⣿⡿⠟⠋⠁⠄⠄⣿⣿⣿⣿"
		$a17 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
		$a18 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
		$a19 = "⣿⣿⣿⠄⠄⠈⠄⠄⠄⣿⣿⣿⠋⠄⠄⠄⠄⠄⢸⣿⣿⣿⣿⣿"
		$a20 = "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
		$b1 = "Your files has been encrypted"
		$b2 = "Telegram @gazpromlock"
		$b3 = "Your decrypt key:"

	condition:
		filesize < 5KB and
		21 of them
}
rule MAL_H0lyGh0st_SiennaPurple_strings {
	meta:
		description = "Matches strings found in SiennaPurple variant of H0lyGh0st ransomware binaries."
		last_modified = "2024-03-17"
		author = "@petermstewart"
		DaysofYara = "77/100"
		sha256 = "99fc54786a72f32fd44c7391c2171ca31e72ca52725c68e2dde94d04c286fccd"
		ref = "https://blogs.blackberry.com/en/2022/08/h0lygh0st-ransomware"

	strings:
		$pdb = "M:\\ForOP\\attack(utils)\\attack tools\\Backdoor\\powershell\\btlc_C\\Release\\btlc_C.pdb"
		$a1 = "matmq3z3hiovia3voe2tix2x54sghc3tszj74xgdy4tqtypoycszqzqd.onion"
		$a2 = "H0lyGh0st@mail2tor.com"
		$b1 = "We are <HolyGhost>"
		$b2 = "All your important files are stored and encrypted"
		$b3 = "Do not try to decrypt using third party software, it may cause permanent data lose"
		$b4 = "To Decrypt all device, Contact us"
		$b5 = "or install tor browser and visit"

	condition:
		uint16(0) == 0x5a4d and
		6 of them
}

rule MAL_H0lyGh0st_SiennaBlue_strings {
	meta:
		description = "Matches strings found in SiennaPurple variant of H0lyGh0st ransomware binaries."
		last_modified = "2024-03-18"
		author = "@petermstewart"
		DaysofYara = "78/100"
		sha256 = "f8fc2445a9814ca8cf48a979bff7f182d6538f4d1ff438cf259268e8b4b76f86"
		sha256 = "bea866b327a2dc2aa104b7ad7307008919c06620771ec3715a059e675d9f40af"
		ref = "https://blogs.blackberry.com/en/2022/08/h0lygh0st-ransomware"

	strings:
		$a = ".h0lyenc"
		$b1 = "Please Read this text to decrypt all files encrypted"
		$b2 = "We have uploaded all files to cloud"
		$b3 = "Don't worry, you can return all of your files immediately if you pay"
		$b4 = "If you want to restore all of your files, Send mail to"
		$b5 = "with your Id. Your ID is"
		$b6 = "Or install tor browser and contact us with your id or "
		$b7 = "(If all of pcs in your company are encrypted)"
		$b8 = "Our site : "
		$b9 = "H0lyGh0stWebsite"
		$b10 = "After you pay, We will send unlocker with decryption key"

	condition:
		uint16(0) == 0x5a4d and
		$a and
		7 of them
}
rule MAL_HuntersInternational_strings {
    meta:
        description = "Matches strings found in Hunters International ransomware samples."
        last_modified = "2024-03-30"
        author = "@petermstewart"
        DaysofYara = "90/100"
        sha256 = "c4d39db132b92514085fe269db90511484b7abe4620286f6b0a30aa475f64c3e"

    strings:
        $a1 = "windows_encrypt/src/main.rs"
        $a2 = "skipped, reserve dir"
        $a3 = "skipped, min size:"
        $a4 = "skipped, symlink:"
        $a5 = "skipped, reserved file:"
        $a6 = "skipped, reserved extension:"
        $a7 = "got, dir:"
        $a8 = "encrypting"

    condition:
        uint16(0) == 0x5a4d and
        all of them
}

rule MAL_HuntersInternational_ransomnote {
    meta:
        description = "Matches strings found in Hunters International ransom notes."
        last_modified = "2024-03-31"
        author = "@petermstewart"
        DaysofYara = "91/100"

    strings:
        $a1 = "_   _ _   _ _   _ _____ _____ ____  ____"
        $a2 = "| | | | | | | \\ | |_   _| ____|  _ \\/ ___|"
        $a3 = "| |_| | | | |  \\| | | | |  _| | |_) \\___ \\"
        $a4 = "|  _  | |_| | |\\  | | | | |___|  _ < ___) |"
        $a5 = "|_|_|_|\\___/|_|_\\_|_|_|_|_____|_|_\\_\\____/____ ___ ___  _   _    _    _"
        $a6 = "|_ _| \\ | |_   _| ____|  _ \\| \\ | |  / \\|_   _|_ _/ _ \\| \\ | |  / \\  | |"
        $a7 = "| ||  \\| | | | |  _| | |_) |  \\| | / _ \\ | |  | | | | |  \\| | / _ \\ | |"
        $a8 = "| || |\\  | | | | |___|  _ <| |\\  |/ ___ \\| |  | | |_| | |\\  |/ ___ \\| |___"
        $a9 = "|___|_| \\_| |_| |_____|_| \\_\\_| \\_/_/   \\_\\_| |___\\___/|_| \\_/_/   \\_\\_____|"
        $b1 = "hunters33mmcwww7ek7q5ndahul6nmzmrsumfs6aenicbqon6mxfiqyd.onion"
        $b2 = "hunters33dootzzwybhxyh6xnmumopeoza6u4hkontdqu7awnhmix7ad.onion"
        $b3 = "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion"
        $b4 = "hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd.onion"

    condition:
        filesize < 5KB and
        all of ($a*) and
        1 of ($b*)
}
rule MAL_Kuiper_strings {
	meta:
		description = "Matches strings found in Stairwell analysis blog post of Kuiper ransomware."
		last_modified = "2024-01-22"
		author = "@petermstewart"
		DaysofYara = "22/100"
		ref = "https://stairwell.com/resources/kuiper-ransomware-analysis-stairwells-technical-report/"

	strings:
		$a1 = "kuiper"
		$a2 = "README_TO_DECRYPT.txt"
		$a3 = "vssadmin delete shadows /all /quiet"
		$a4 = "wevtutil cl application"
		$a5 = "wbadmin delete catalog -quiet"
		$a6 = "bcdedit /set {default} recoveryenabled No"
		$a7 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest"
		$a8 = "wevtutil cl securit"
		$a9 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
		$a10 = "wbadmin DELETE SYSTEMSTATEBACKUP"
		$a11 = "wevtutil cl system"
		$a12 = "vssadmin resize shadowstorage /for="
		$a13 = "\\C$\\Users\\Public\\safemode.exe"
		$a14 = "process call create \"C:\\Users\\Public\\safemode.exe -reboot no\""

	condition:
		uint16(0) == 0x5a4d and
		10 of them
}

rule MAL_Kuiper_ransomnote {
	meta:
		description = "Matches strings found in Stairwell analysis blog post of Kuiper ransomware."
		last_modified = "2024-01-23"
		author = "@petermstewart"
		DaysofYara = "23/100"
		ref = "https://stairwell.com/resources/kuiper-ransomware-analysis-stairwells-technical-report/"

	strings:
		$tox = "D27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1B9803AAC6ECF9"
		$email = "kuipersupport@onionmail.org"
		$a1 = "Your network has been compromised! All your important data has been encrypted!"
		$a2 = "There is  only one way to get your data back to normal:"
		$a3 = "1. Contact us as soon as possible to avoid damages and losses from your business."
		$a4 = "2. Send to us any encrypted file of your choice and your personal key."
		$a5 = "3. We will decrypt 1 file for test (maximum file size = 1 MB), its guaranteed that we can decrypt your files."
		$a6 = "4. Pay the amount required in order to restore your network back to normal."
		$a7 = "5. We will then send you our software to decrypt and will guide you through the whole restoration of your network."
		$a8 = "We prefer Monero (XMR) - FIXED PRICE"
		$a9 = "We accept Bitcoin (BTC) - 20% extra of total payment!"
		$a10 = "WARNING!"
		$a11 = "Do not rename encrypted data."
		$a12 = "Do not try to decrypt using third party software, it may cause permanent data loss not being able to recover."
		$a13 = "Contact information:"
		$a14 = "In order to contact us, download with the following software: https://qtox.github.io or https://tox.chat/download.html"
		$a15 = "Then just add us in TOX:"
		$a16 = "Your personal id:"
		$a17 = "--------- Kuiper Team ------------"

	condition:
		filesize < 5KB and
		15 of them
}
rule MAL_Lckmac_strings {
    meta:
        description = "Matches function name strings found in MachO ransomware sample uploaded to VirusTotal with filename 'lckmac'."
        last_modified = "2024-03-16"
        author = "@petermstewart"
        DaysofYara = "76/100"
        sha256 = "e02b3309c0b6a774a4d940369633e395b4c374dc3e6aaa64410cc33b0dcd67ac"
        ref = "https://x.com/malwrhunterteam/status/1745144586727526500"

    strings:
        $a1 = "main.parsePublicKey"
        $a2 = "main.writeKeyToFile"
        $a3 = "main.getSystemInfo"
        $a4 = "main.EncryptTargetedFiles"
        $a5 = "main.shouldEncryptFile"
        $a6 = "main.encryptFile"
        $a7 = "main.deleteSelf"

    condition:
        (uint32(0) == 0xfeedface or     //MH_MAGIC
        uint32(0) == 0xcefaedfe or      //MH_CIGAM
        uint32(0) == 0xfeedfacf or      //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or      //MH_CIGAM_64
        uint32(0) == 0xcafebabe or      //FAT_MAGIC
        uint32(0) == 0xbebafeca) and    //FAT_CIGAM
        all of them
}
rule MAL_Lockbit_2_Win_strings {
	meta:
		description = "Matches strings found in Lockbit 2.0 ransomware Windows samples."
		last_modified = "2024-01-17"
		author = "@petermstewart"
		DaysofYara = "17/100"
		sha256 = "36446a57a54aba2517efca37eedd77c89dfc06e056369eac32397e8679660ff7"
		sha256 = "9feed0c7fa8c1d32390e1c168051267df61f11b048ec62aa5b8e66f60e8083af"

	strings:
		$a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide
		$b1 = "All your files stolen and encrypted" wide
		$b2 = "for more information see" wide
		$b3 = "RESTORE-MY-FILES.TXT" wide
		$b4 = "that is located in every encrypted folder." wide
		$b5 = "You can communicate with us through the Tox messenger" wide
		$b6 = "If you want to contact us, use ToxID" wide

	condition:
		filesize > 800KB and filesize < 10MB and
		uint16(0) == 0x5a4d and
		$a and
		4 of ($b*)
}

rule MAL_Lockbit_2_macOS_strings {
	meta:
		description = "Matches strings found in Lockbit ransomware macOS sample."
		last_modified = "2024-01-18"
		author = "@petermstewart"
		DaysofYara = "18/100"
		sha256 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"

	strings:
		$a1 = "lockbit"
		$a2 = "restore-my-files.txt"
		$a3 = "_I_need_to_bypass_this_"
		$a4 = "kLibsodiumDRG"
		$b = "_Restore_My_Files_"

	condition:
		filesize < 500KB and
		(uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		#b > 4 and
		all of ($a*)
}

rule MAL_Lockbit_2_ransomnote {
	meta:
		description = "Matches strings found in Lockbit 2.0 ransom note samples."
		last_modified = "2024-01-19"
		author = "@petermstewart"
		DaysofYara = "19/100"

	strings:
		$a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion"
		$b1 = "https://bigblog.at"
		$b2 = "http://lockbitsup4yezcd5enk5unncx3zcy7kw6wllyqmiyhvanjj352jayid.onion"
		$b3 = "http://lockbitsap2oaqhcun3syvbqt6n5nzt7fqosc6jdlmsfleu3ka4k2did.onion"
		$c1 = "LockBit 2.0 Ransomware"
		$c2 = "Your data are stolen and encrypted"
		$c3 = "The data will be published on TOR website"
		$c4 = "if you do not pay the ransom"
		$c5 = "You can contact us and decrypt on file for free on these TOR sites"
		$c6 = "Decryption ID:"

	condition:
		filesize < 5KB and
		$a and
		2 of ($b*) and
		5 of ($c*)
}
rule MAL_NoVirus_strings {
	meta:
		description = "Matches strings found in ransomware sample uploaded to VirusTotal with filename 'no virus.exe'."
		last_modified = "2024-02-25"
		author = "@petermstewart"
		DaysofYara = "56/100"
		sha256 = "015e546f3ac1350c5b68fedc89e16334a4e456092228e691f054c1a86fefb6c6"
		ref = "https://x.com/malwrhunterteam/status/1745182178474885199"

	strings:
		$a1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide
		$a2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" wide
		$a3 = "wbadmin delete catalog -quiet" wide
		$b1 = "read_it.txt" wide
		$b2 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" wide
		$c1 = "Don't worry, you can return all your files!" wide
		$c2 = "All your files like documents, photos, databases and other important are encrypted" wide
		$c3 = "You must follow these steps To decrypt your files" wide
		$c4 = "1) CONTACT US Telegram @CryptoKeeper_Support" wide
		$c5 = "2) Obtain Bitcoin (You have to pay for decryption in Bitcoins." wide
		$c6 = "After payment we will send you the tool that will decrypt all your files.)" wide
		$c7 = "3) Send 500$ worth of btc to the next address:" wide
		$c8 = "17Ym1FfiuXGGWr1SN6enUEEZUwnsuNMUDa" wide

	condition:
		uint16(0) == 0x5a4d and
		8 of them
}
rule MAL_Royal_strings {
	meta:
		description = "Matches strings found in Windows and Linux samples of Royal ransomware."
		last_modified = "2024-01-20"
		author = "@petermstewart"
		DaysofYara = "20/100"
		sha256 = "312f34ee8c7b2199a3e78b4a52bd87700cc8f3aa01aa641e5d899501cb720775"
		sha256 = "9db958bc5b4a21340ceeeb8c36873aa6bd02a460e688de56ccbba945384b1926"
		sha256 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"

	strings:
		$a = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion"
		$b1 = "If you are reading this, it means that your system were hit by Royal ransomware"
		$b2 = "Please contact us via :"
		$b3 = "In the meantime, let us explain this case"
		$b4 = "It may seem complicated, but it is not!"
		$b5 = "Most likely what happened was that you decided to save some money on your security infrastructure"
		$b6 = "Alas, as a result your critical data was not only encrypted but also copied from your systems on a secure server"
		$b7 = "From there it can be published online"
		$b8 = "Then anyone on the internet from darknet criminals, ACLU journalists, Chinese government"
		$b9 = "and even your employees will be able to see your internal documentation: personal data, HR reviews, internal lawsuitsand complains, financial reports, accounting, intellectual property, and more"
		$b10 = "Fortunately we got you covered!"
		$b11 = "Royal offers you a unique deal.For a modest royalty(got it; got it ? )"
		$b12 = "Try Royal today and enter the new era of data security"
		$b13 = "We are looking to hearing from you soon"

	condition:
		filesize > 2000KB and filesize < 3500KB and
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		$a and
		10 of ($b*)
}

rule MAL_Royal_ransomnote {
	meta:
		description = "Matches strings found in Royal ransom note sample."
		last_modified = "2024-01-21"
		author = "@petermstewart"
		DaysofYara = "21/100"

	strings:
		$a = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion"
		$b1 = "If you are reading this, it means that your system were hit by Royal ransomware"
		$b2 = "Please contact us via :"
		$b3 = "In the meantime, let us explain this case"
		$b4 = "It may seem complicated, but it is not!"
		$b5 = "Most likely what happened was that you decided to save some money on your security infrastructure"
		$b6 = "Alas, as a result your critical data was not only encrypted but also copied from your systems on a secure server"
		$b7 = "From there it can be published online"
		$b8 = "Then anyone on the internet from darknet criminals, ACLU journalists, Chinese government"
		$b9 = "and even your employees will be able to see your internal documentation: personal data, HR reviews, internal lawsuitsand complains, financial reports, accounting, intellectual property, and more"
		$b10 = "Fortunately we got you covered!"
		$b11 = "Royal offers you a unique deal.For a modest royalty(got it; got it ? )"
		$b12 = "for our pentesting services we will not only provide you with an amazing risk mitigation service"
		$b13 = "covering you from reputational, legal, financial, regulatory, and insurance risks, but will also provide you with a security review for your systems"
		$b14 = "To put it simply, your files will be decrypted, your data restoredand kept confidential, and your systems will remain secure"
		$b15 = "Try Royal today and enter the new era of data security"
		$b16 = "We are looking to hearing from you soon"

	condition:
		filesize < 5KB and
		1 of ($a*) and
		13 of ($b*)
}
rule MAL_Trigona_strings {
    meta:
        description = "Matches strings found in Trigona ransomware samples."
        last_modified = "2024-03-28"
        author = "@petermstewart"
        DaysofYara = "88/100"
        sha256 = "fb128dbd4e945574a2795c2089340467fcf61bb3232cc0886df98d86ff328d1b"
        sha256 = "d743daa22fdf4313a10da027b034c603eda255be037cb45b28faea23114d3b8a"

    strings:
        $a1 = "how_to_decrypt" wide
        $b1 = "nolocal"
        $b2 = "nolan"
        $b3 = "shutdown"
        $b4 = "random_file_system"
        $b5 = "fullmode"
        $b6 = "erasemode"
        $b7 = "network_scan_finished"
        $b8 = "is_testing"

    condition:
        uint16(0) == 0x5a4d and
        $a1 and
        4 of ($b*)
}

rule MAL_Trigona_ransomnote {
    meta:
        description = "Matches strings found in Trigona ransom notes."
        last_modified = "2024-03-29"
        author = "@petermstewart"
        DaysofYara = "89/100"

    strings:
        $a1 = "3x55o3u2b7cjs54eifja5m3ottxntlubhjzt6k6htp5nrocjmsxxh7ad.onion"
        $b1 = "<title>ENCRYPTED</title>"
        $b2 = "the entire network is encrypted"
        $b3 = "your business is losing money"
        $b4 = "All documents, databases, backups and other critical data were encrypted and leaked"
        $b5 = "The program uses a secure AES algorithm"
        $b6 = "decryption impossible without contacting us"
        $b7 = "To recover your data, please follow the instructions"
        $b8 = "Download Tor Browser"
        $b9 = "Open decryption page"
        $b10 = "Auth using this key"

    condition:
        filesize < 20KB and
        7 of them
}
rule MAL_TurtleRansom_strings {
    meta:
        description = "Matches strings found in Windows, ELF, and MachO Turtle ransomware samples."
        last_modified = "2024-01-26"
        author = "@petermstewart"
        DaysofYara = "26/100"
        sha256 = "b384155b74845beeea0f781c9c216c69eceb018520d819dd09823cff6ef0e7de"
        sha256 = "f5b9b80f491e5779f646d2510a2c9c43f3072c45302d271798c4875544ace4f2"
        sha256 = "df5f7570bf0b1f99f33c31913ab9f25b9670286e8e2462278aea2157f8173a68"
        sha256 = "b5ab9c61c81dfcd2242b615c9af2cb018403c9a784b7610b39ed56222d669297"
        sha256 = "a4789e0b79a8bac486fbc3b0f00b6dcbaac6854e621d40fc3005d23f83d2e5ec"
        sha256 = "5f9cd91d8d1dcfe2f6cf4c6995ad746694ce57023dfb82b1cd6af5697113d1b0"
        sha256 = "a48af4a62358831fe5376aa52db1a3555b0c93c1665b242c0c1f49462f614c56"
        sha256 = "62f84afdab28727ab47b5c1e4af92b33dc2b11e55dca7b097fe94da5bcc9ec4e"
        sha256 = "f14ef1c911deb8714d1bb501064505c13237049ac51f0a657da4b0bf11f5f59e"
        sha256 = "65eea957148d75c29213dff0c5465c6dc1db266437865538cfe8744c2436f5e1"
        sha256 = "00b52a5905e042a9a9f365f7e5404f420ae26f463f24c069d6076e9094f61a8e"
        sha256 = "52337055cca751b8b2b716a1c8f3ba179ddd74b268b67641ade223d3d3cf773d"
        ref = "https://objective-see.org/blog/blog_0x76.html"

    strings:
        $a1 = "D:/VirTest/TurmiRansom/main.go"
        $a2 = "VirTest/TurmiRansom"
        $a3 = "TurmiRansom/main.go"
        $b1 = "TURTLERANSv0"
        $b2 = "wugui123"
        $b3 = "main..inittask"
        $b4 = "main.en0cr0yp0tFile"
        $b5 = "main.main"
        $b6 = "main.main.func1"

    condition:
        (uint16(0) == 0x5a4d or         //PE
        uint32(0) == 0x464c457f or      //ELF
        uint32(0) == 0xfeedface or      //MH_MAGIC
        uint32(0) == 0xcefaedfe or      //MH_CIGAM
        uint32(0) == 0xfeedfacf or      //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or      //MH_CIGAM_64
        uint32(0) == 0xcafebabe or      //FAT_MAGIC
        uint32(0) == 0xbebafeca) and    //FAT_CIGAM
        2 of ($a*) and
        all of ($b*)
}
rule MAL_Yanluowang_strings {
    meta:
        description = "Matches function name strings found in Yanluowang ransomware samples."
        last_modified = "2024-03-26"
        author = "@petermstewart"
        DaysofYara = "86/100"
        sha256 = "49d828087ca77abc8d3ac2e4719719ca48578b265bbb632a1a7a36560ec47f2d"
        sha256 = "d11793433065633b84567de403c1989640a07c9a399dd2753aaf118891ce791c"

    strings:
        $a1 = "C:\\Users\\111\\Desktop\\wifi\\project\\ConsoleApplication2\\Release\\ConsoleApplication2.pdb"
        $a2 = "C:\\Users\\cake\\Desktop\\project-main\\project-main\\ConsoleApplication2\\cryptopp-master"
        $a3 = "Syntax: encrypt.exe [(-p,-path,--path)<path>]"
        $a4 = "yanluowang"

    condition:
        uint16(0) == 0x5a4d and
        all of them
}

rule MAL_Yanluowang_ransomnote {
    meta:
        description = "Matches strings found in Yanluowang ransom notes."
        last_modified = "2024-03-27"
        author = "@petermstewart"
        DaysofYara = "87/100"

    strings:
        $a1 = "since you are reading this it means you have been hacked"
        $a2 = "encrypting all your systems"
        $a3 = "Here's what you shouldn't do"
        $a4 = "Do not try to decrypt the files yourself"
        $a5 = "do not change the file extension yourself"
        $a6 = "Keep us for fools"
        $a7 = "Here's what you should do right after reading it"
        $a8 = "send our message to the CEO of the company, as well as to the IT department"
        $a9 = "you should contact us within 24 hours by email"
        $a10 = "As a guarantee that we can decrypt the files, we suggest that you send several files for free decryption"
        $a11 = "Mails to contact us"

    condition:
        filesize < 5KB and
        8 of them
}
rule PUP_Cloudflare_tunnel_strings {
    meta:
        description = "Matches strings found in Cloudflare Tunnel client binaries, often abused by threat actors."
        last_modified = "2024-03-21"
        author = "@petermstewart"
        DaysofYara = "81/100"
        sha256 = "92ec16e1226249fcb7f07691a3e6d8fbb0f4482c786c4cff51b4ecab3e1a3a86"
        sha256 = "05cead663a846504ca20d73abede2e97c7cae59b3975fb6dbe89840d57abc5d7"
        ref = "https://github.com/cloudflare/cloudflared"

    strings:
        $a1 = "cloudflared connects your machine or user identity to Cloudflare's global network"
        $a2 = "Use Cloudflare Tunnel to expose private services to the Internet or to Cloudflare connected private users."
        $a3 = "[global options] [command] [command options]"

    condition:
        all of them
}
import "pe"
import "hash"

rule PUP_THCHydra_strings {
    meta:
        description = "Matches strings found in the THC-Hydra network scanner."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        ref = "https://github.com/vanhauser-thc/thc-hydra"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    strings:
        $a1 = "hydra -P pass.txt target cisco-enable  (direct console access)"
        $a2 = "hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)"
        $a3 = "hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login foo, password bar)"
        $a4 = "hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass"
        $a5 = "hydra -L urllist.txt http-proxy-urlenum://target.com:3128/user:pass"
        $a6 = "USER hydra%d hydra %s :hydra"
        $a7 = "hydra rdp://192.168.0.1/firstdomainname -l john -p doe"
        $a8 = "User-Agent: Mozilla/4.0 (Hydra)"

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        all of them
}

rule PUP_THCHydra_default_icon {
    meta:
        description = "Matches the default icon resource section hash found in Windows THC-Hydra network scanner binaries."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        sha256 = "ee43a7be375ae2203b635c569652f182f381b426f80430ee495aa6a96f37b4e6"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    condition:
        uint16(0) == 0x5a4d and
        for any resource in pe.resources:
        (
            hash.md5(resource.offset, resource.length) == "7835bdbf054e7ba813fa0203aa1c5e36"
        )
}

rule PUP_AdvancedIPScanner_strings {
	meta:
		description = "Matches strings found in the Advanced IP Scanner installer, often abused by malicious actors."
		last_modified = "2024-03-10"
		author = "@petermstewart"
		DaysofYara = "70/100"
		sha256 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b"

	strings:
		$a1 = "This installer contains the logic and data to install Advanced IP Scanner"
		$a2 = "www.advanced-ip-scanner.com/link.php?"
		$a3 = "advanced ip scanner; install; network scan; ip scan; LAN"

	condition:
		uint16(0) == 0x5a4d and
		all of them
}
rule PUP_RMM_ScreenConnect_msi {
	meta:
		description = "Matches strings found in ScreenConnect MSI packages, often abused for unauthorised access."
		last_modified = "2024-03-02"
		author = "@petermstewart"
		DaysofYara = "62/100"
		sha256 = "80b6ec0babee522290588e324026f7c16e3de9d178b9e846ae976ab432058ce7"
		sha256 = "f8c2b122da9c9b217eada5a1e5fde92678925f1bb2ea847253538ffda274f0b9"

	strings:
		$magic = { d0 cf 11 e0 a1 b1 1a e1 }
		$clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$a1 = "ScreenConnect.Client.dll"
		$a2 = "ScreenConnect.WindowsClient.exe"
		$a3 = "Share My Desktop"
		$a4 = "Grab a still image of the remote machine desktop"

	condition:
		$magic at 0 and
		all of them
}

rule PUP_RMM_AnyDesk_exe {
	meta:
		description = "Matches AnyDesk remote management tool, often abused for unauthorised access."
		last_modified = "2024-03-03"
		author = "@petermstewart"
		DaysofYara = "63/100"
		sha256 = "5beab9f13976d174825f9caeedd64a611e988c69f76e63465ed10c014de4392a"
		sha256 = "7a719cd40db3cf7ed1e4b0d72711d5eca5014c507bba029b372ade8ca3682d70"

	strings:
		$pdb = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb"
		$a1 = "my.anydesk.com"
		$a2 = "AnyDesk Software GmbH" wide

	condition:
		uint16(0)==0x5a4d and
		all of them
}

rule PUP_RMM_AteraAgent_msi {
	meta:
		description = "Matches strings found in Atera Agent remote management tool installer, often abused for unauthorised access."
		last_modified = "2024-03-04"
		author = "@petermstewart"
		DaysofYara = "64/100"
		sha256 = "91d9c73b804aae60057aa93f4296d39ec32a01fe8201f9b73f979d9f9e4aea8b"

	strings:
		$magic = { d0 cf 11 e0 a1 b1 1a e1 }
		$clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$a1 = "AteraAgent"
		$a2 = "This installer database contains the logic and data required to install AteraAgent."

	condition:
		$magic at 0 and
		all of them
}
rule TTP_delete_volume_shadow {
	meta:
		description = "Matches references to 'vssadmin delete' commands - used to remove Volume Shadow Copies."
		last_modified = "2024-03-13"
		author = "@petermstewart"
		DaysofYara = "73/100"

	strings:
		$a = "vssadmin delete" ascii wide nocase
		$b = "vssadmin.exe delete" ascii wide nocase

	condition:
		uint16(0) == 0x5a4d and
		any of them
}

rule TTP_clear_event_logs {
	meta:
		description = "Matches references to 'wevtutil' or 'Clear-Eventlog' - used to clear Windows Event Logs."
		last_modified = "2024-03-14"
		author = "@petermstewart"
		DaysofYara = "74/100"

	strings:
		$a = "wevtutil cl" ascii wide nocase
		$b = "wevtutil.exe cl" ascii wide nocase
		$c = "wevtutil clear log" ascii wide nocase
		$d = "wevtutil.exe clear log" ascii wide nocase
		$e = "Clear-EventLog" ascii wide nocase //PowerShell

	condition:
		uint16(0) == 0x5a4d and
		any of them
}

rule TTP_bcdedit_safeboot_cmd {
	meta:
		description = "Matches bcdedit command used to configure reboot to safemode - can be used to bypass security tools."
		last_modified = "2024-03-15"
		author = "@petermstewart"
		DaysofYara = "75/100"

	strings:
		$a = "bcdedit /set {default} safeboot" ascii wide nocase
		$b = "bcdedit.exe /set {default} safeboot" ascii wide nocase

	condition:
		uint16(0) == 0x5a4d and
		any of them
}
rule TTP_contains_onion_address {
	meta:
		description = "Matches regex for .onion addresses associated with Tor Hidden Services."
		last_modified = "2024-01-11"
                author = "@petermstewart"
                DaysofYara = "11/100"

	strings:
		$r1 = /[a-z2-7]{16}\.onion/ fullword ascii wide
		$r2 = /[a-z2-7]{55}d\.onion/ fullword ascii wide

	condition:
		filesize < 5MB and
		any of them
}
rule TTP_contains_BTC_address {
	meta:
		description = "Matches regex for Bitcoin wallet addresses."
		last_modified = "2024-01-08"
        	author = "@petermstewart"
        	DaysofYara = "8/100"

	strings:
		$r1 = /(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}

rule TTP_contains_ETH_address {
	meta:
		description = "Matches regex for Ethereum wallet addresses."
		last_modified = "2024-01-09"
        	author = "@petermstewart"
        	DaysofYara = "9/100"

	strings:
		$r1 = /0x[a-fA-F0-9]{40}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}

rule TTP_contains_XMR_address {
	meta:
		description = "Matches regex for Monero wallet addresses."
		last_modified = "2024-01-10"
        	author = "@petermstewart"
        	DaysofYara = "10/100"

	strings:
		$r1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}
rule TTP_cryptominer_stratum_strings {
	meta:
		description = "Matches stratum URL strings commonly found in cryptominers."
		last_modified = "2024-02-01"
		author = "@petermstewart"
		DaysofYara = "32/100"

	strings:
		$a1 = "stratum+tcp" ascii wide
		$a2 = "stratum+udp" ascii wide
		$a3 = "stratum+ssl" ascii wide

	condition:
		(uint16(0) == 0x5a4d or 		//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		any of them
}
rule TTP_BITS_Download_command {
	meta:
		description = "Matches strings commonly found when creating new BITS download jobs."
		last_modified = "2024-02-19"
		author = "@petermstewart"
		DaysofYara = "50/100"
		ref = "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"

	strings:
		$a = "bitsadmin /create" nocase ascii wide
		$b = "/addfile" nocase ascii wide
		$c = "/complete" nocase ascii wide
		$d = "http" nocase ascii wide

	condition:
		all of them
}

rule TTP_PowerShell_Download_command {
	meta:
		description = "Matches strings commonly found in PowerShell download cradles."
		last_modified = "2024-02-20"
		author = "@petermstewart"
		DaysofYara = "51/100"
		ref = "https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters"

	strings:
		$a = "powershell" nocase ascii wide
		$b = "IEX" nocase ascii wide
		$c = "New-Object" nocase ascii wide
		$d = "Net.Webclient" nocase ascii wide
		$e = ".downloadstring(" nocase ascii wide

	condition:
		4 of them
}

rule TTP_Certutil_Download_command {
	meta:
		description = "Matches strings commonly found in certutil.exe download commands."
		last_modified = "2024-02-21"
		author = "@petermstewart"
		DaysofYara = "52/100"
		ref = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download"

	strings:
		$a = "certutil" nocase ascii wide
		$b = "-urlcache" nocase ascii wide
		$c = "-split" nocase ascii wide
		$d = "http" nocase ascii wide

	condition:
		all of them
}
import "pe"

rule TTP_WIP19_bad_cert {
	meta:
		description = "Matches known bad signing certificate serial number used by China-nexus threat actor WIP19."
		last_modified = "2024-01-05"
    		author = "@petermstewart"
    		DaysofYara = "5/100"
		ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
		sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"
		sha256 = "2f2f165ee5b81a101ebda0b161f43b54bc55afd8e4702c9b8056a175a1e7b0e0"
		
	condition:
		uint16(0) == 0x5a4d and
		pe.number_of_signatures > 0 and
		for any sig in pe.signatures:
		(
			sig.serial == "02:10:36:b9:e8:0d:16:ea:7f:8c:f0:e9:06:2b:34:55"
		)
}
import "pe"
import "hash"
rule APT_IR_ShroudedSnooper_XORd_Config_In_Data_Sect
{
	meta:
		author = "Greg Lesnewich"
		description = "track ShroudedSnooper toolset based on repeated XOR encoded .data section "
		date = "2023-10-02"
		version = "1.0"
		DaysofYARA = "7/100"
		HTTPSnoop_hash = "3875ed58c0d42e05c83843b32ed33d6ba5e94e18ffe8fb1bf34fd7dedf3f82a7"
		HTTPSnoop_hash = "7495c1ea421063845eb8f4599a1c17c105f700ca0671ca874c5aa5aef3764c1c"
		HTTPSnoop_hash = "c5b4542d61af74cf7454d7f1c8d96218d709de38f94ccfa7c16b15f726dc08c0"
		PipeSnoop_hash = "9117bd328e37be121fb497596a2d0619a0eaca44752a1854523b8af46a5b0ceb"
		PipeSnoop_hash = "e1ad173e49eee1194f2a55afa681cef7c3b8f6c26572f474dec7a42e9f0cdc9d"
		reference = "https://blog.talosintelligence.com/introducing-shrouded-snooper/"

	condition:
		for any sect in pe.sections:
		(
			sect.name == ".data" and
			uint8(sect.raw_data_offset) == uint8(sect.raw_data_offset + 4) and
			uint32be(sect.raw_data_offset) != 0x0 and
			(
				//HTTPSnoop Variant
				(
					uint8(sect.raw_data_offset+0x40) ^ uint8be(sect.raw_data_offset) == 0x2f and
					uint8(sect.raw_data_offset+0x42) ^ uint8be(sect.raw_data_offset) == 0x2f and
					uint8(sect.raw_data_offset+0x41) == uint8be(sect.raw_data_offset)
				) or
				( //PipeSnoop Variant
					uint8(sect.raw_data_offset+0x34) ^ uint8be(sect.raw_data_offset) == 0x5c and
					uint8(sect.raw_data_offset+0x36) ^ uint8be(sect.raw_data_offset) == 0x5c and
					uint8(sect.raw_data_offset+0x38) ^ uint8be(sect.raw_data_offset) == 0x2e and
					uint8(sect.raw_data_offset+0x35) == uint8be(sect.raw_data_offset)
					)
			)
			)
}
rule APT_NK_TA444_SpectralBlur
{
	meta:
		author = "Greg Lesnewich"
		description = "track the SpectralBlur backdoor"
		date = "2023-08-21"
		version = "1.0"
		hash = "6f3e849ee0fe7a6453bd0408f0537fa894b17fc55bc9d1729ae035596f5c9220"
		DaysofYARA = "3/100"

	strings:
		$xcrypt1 = {
			99                 // cdq
			f7 [4-8]           // idiv    dword [rbp-0x11c {var_124}]
			8b [4-8]           // mov     eax, dword [rbp-0x14c {var_154_1}]
			48 63 d2           // movsxd  rdx, edx
			0f b6 0c 11        // movzx   ecx, byte [rcx+rdx]
			01 c8              // add     eax, ecx
			b9 00 01 00 00     // mov     ecx, 0x100
			99                 // cdq
			f7 f9              // idiv    ecx
		}

		$xcrypt2 = {
			8b 85 c4 fe ff ff        // mov     eax, dword [rbp-0x13c {var_144_2}]
			83 c0 01                 // add     eax, 0x1
			b9 00 01 00 00           // mov     ecx, 0x100
			99                       // cdq
			f7 f9                    // idiv    ecx
			[20-40]
			01 c8                    // add     eax, ecx
			b9 00 01 00 00           // mov     ecx, 0x100
			99                       // cdq
			f7 f9                    // idiv    ecx
		}

		$symbol1 = "xcrypt" ascii wide
		$symbol2 = "_proc_die" ascii wide
		$symbol3 = "_proc_dir" ascii wide
		$symbol4 = "_proc_download" ascii wide
		$symbol5 = "_proc_download_content" ascii wide
		$symbol6 = "_proc_getcfg" ascii wide
		$symbol7 = "_proc_hibernate" ascii wide
		$symbol8 = "_proc_none" ascii wide
		$symbol9 = "_proc_restart" ascii wide
		$symbol10 = "_proc_rmfile" ascii wide
		$symbol11 = "_proc_setcfg" ascii wide
		$symbol12 = "_proc_shell" ascii wide
		$symbol13 = "_proc_sleep" ascii wide
		$symbol14 = "_proc_stop" ascii wide
		$symbol15 = "_proc_testconn" ascii wide
		$symbol16 = "_proc_upload" ascii wide
		$symbol17 = "_proc_upload_content" ascii wide
		$symbol18 = "_sigchild" ascii wide

		$string1 = "/dev/null" ascii wide
		$string2 = "SHELL" ascii wide
		$string3 = "/bin/sh" ascii wide
		$string4 = {2573200a2573200a2573200a2573200a2573200a2573200a2573200a257320} // %s with repeating new lines string
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		(any of ($xcrypt*) or 4 of ($symbol*) or (all of ($string*)))
}
rule APT_NK_UNC4034_TrojanizedPutty_BLINDINGCAN {

    meta:
        description = "track trojanized instances of Putty dropping BLINDINGCAN"
        author = "Greg Lesnewich"
        date = "2022-09-15"
        version = "1.0"
        reference = "https://www.mandiant.com/resources/blog/dprk-whatsapp-phishing"
        hash = "cf22964951352c62d553b228cf4d2d9efe1ccb51729418c45dc48801d36f69b4"
        hash = "1492fa04475b89484b5b0a02e6ba3e52544c264c294b57210404b96b65e63266"
    strings:
        $exe1 = "schtasks.exe"
        $exe2 = "C:\\ProgramData\\PackageColor\\colorcpl.exe"
        $schtask = "/CREATE /SC DAILY /MO 1 /ST 10:30 /TR"
        $sc1 = "/CREATE /SC"
        $sc2 = "DAILY /MO 1"
        $sc3 = "/ST 10:30 /TR"
        $sc4 = "/TN PackageColor /F"

    condition:
        all of ($exe*) and ($schtask or 3 of ($sc*)) and
        pe.version_info["OriginalFilename"] == "PuTTY"
        and hash.md5(pe.rich_signature.clear_data) == "abe46a9066a76a1ae9e5d70262510bda"
        and for any rsrc in pe.resources: (hash.sha256(rsrc.offset, rsrc.length) == "89101ef80cb32eccdb988e8ea35f93fe4c04923023ad5c9d09d6dbaadd238073")

}
rule APT_RU_TA422_EchoLaunch
{
	meta:
		author = "Greg Lesnewich"
		description = "track TA422's EchoLaunch scriptlet launcher"
		date = "2023-11-29"
		version = "1.4"
		DaysofYARA = "8/100"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/ta422s-dedicated-exploitation-loop-same-week-after-week"
		reference = "https://securityintelligence.com/x-force/itg05-ops-leverage-israel-hamas-conflict-lures-to-deliver-headlace-malware/"
		hash = "742ba041a0870c07e094a97d1c7fd78b7d2fdf0fcdaa709db04e2637a4364185"
		hash = "8a21077dbba184dc43576a78bf52dc29aaa47df332d1e65694876dd245f35563"
		hash = "b26726448878ffba939c95d01252f62b8c004b51a2c8c8cf48ef2c4f308c1721"
		hash = "c89735e787dd223dac559a95cac9e2c0b6ca75dc15da62199c98617b5af007d3"
	strings:
		$s1 = "echo On Error Resume Next & echo .Run" ascii
		$s2 = "CreateObject^(^\"WScript.shell^\"^)" ascii
		$s3 = ".bat^\"^\"^\"^" ascii
		$s4 = "echo taskkill /im msedge.exe /f" ascii
		$s5 = "echo timeout 5 & echo del /q /f" ascii
		$s6 = "msedge --headless=new --disable-gpu data:text/html;base64" ascii
		$s7 = "echo goto loop" ascii
		$s8 = "> nul 2>&1" ascii
		$s9 = "del /F /A /Q" ascii
		$s10 = "taskkill /F /IM" ascii
		$s11 = "echo move /y \"%userprofile%\\Downloads\\*.css\"" ascii
	condition:
		uint32be(0x0) == 0x40656368 and
		uint32be(filesize - 4) == 0x69740d0a and
		filesize < 3000 and 
		9 of them
}
import "pe"

rule APT_RU_Turla_TinyTurlaNG_RichHeader {
    meta:
        description = "track TinyTurlaNG based build artifacts & ServiceDLL components"
        author = "Greg Lesnewich"
        date = "2024-02-15"
        version = "1.0"
        reference = "https://blog.talosintelligence.com/tinyturla-next-generation/"
        hash = "d6ac21a409f35a80ba9ccfe58ae1ae32883e44ecc724e4ae8289e7465ab2cf40"
        hash = "267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b"
        DaysOfYARA = "45/100"

    condition:
        pe.exports("ServiceMain")
        and pe.dll_name == "out.dll"
        and pe.rich_signature.toolid(259,27412) == 10 // MASM Visual Studio 2015 14.0
        and pe.rich_signature.toolid(260,27412) == 19 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(261,27412) == 155 //STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(260,30034) == 14 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(259,30034) == 10 // MASM Visual Studio 2015 14.0
        and pe.rich_signature.toolid(261,30034) >= 70 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(257,27412) >= 6 // IMPORT Visual Studio 2015 14.0
        and pe.rich_signature.toolid(261,30038) >= 7 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(256,30038) == 1 // EXPORT Visual Studio 2015 14.0
        and pe.rich_signature.toolid(255,30038) == 1 // CVTRES Visual Studio 2015 14.0
        and pe.rich_signature.toolid(258,30038) == 1 // LINKER Visual Studio 2015 14.0
}
import "pe"
import "dotnet"

rule APT_RU_TurlaDaddy_Tunnus_Dotnet_RC4_Meta
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-06"
        reference = "https://www.mandiant.com/resources/blog/turla-galaxy-opportunity"
        version = "1.0"
        hash = "0fc624aa9656a8bc21731bfc47fd7780da38a7e8ad7baf1529ccd70a5bb07852"
        DaysofYARA = "6/100"


    condition:
        for any classy in dotnet.classes: (classy.name == "RC4Encryption") or

        for any item in dotnet.classes: ( for any meths in item.methods: (
            meths.name == "EncryptDecrypt"
            ))

}
rule INFO_7z_File
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-22"
        version = "1.0"
        DaysOfYara = "22/100"

    condition:
        uint16be(0x0) == 0x377A
}
import "pe"

rule INFO_DelayedImport_ADVAPI32_Registry
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-08"
        version = "1.0"
        DaysofYARA = "8/100"

    condition:
        for any item in pe.delayed_import_details : (
            item.library_name == "ADVAPI32.dll" and for any api in item.functions:
            (
                api.name startswith "Reg"
                ) )
}


rule INFO_DelayedImport_ADVAPI32_Crypt
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-08"
        version = "1.0"
        DaysofYARA = "8/100"

    condition:
        for any item in pe.delayed_import_details : (
            item.library_name == "ADVAPI32.dll" and for any api in item.functions:
            (
                api.name startswith "Crypt"
                ) )
}
rule INFO_ELF_Contains_iptables
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-21"
        version = "1.0"
        description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
        DaysofYARA = "21/100"

    strings:
        $ = "iptables" ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}


rule INFO_ELF_Contains_iptables_b64
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-21"
        version = "1.0"
        description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
        DaysofYARA = "21/100"

    strings:
        $ = "iptables" base64 base64wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}


rule INFO_ELF_Contains_iptables_xor
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-21"
        version = "1.0"
        description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
        DaysofYARA = "21/100"

    strings:
        $ = "iptables" xor(0x01-0xff) ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_ELF_Contains_HTML_Page
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to HTML"
        DaysofYARA = "16/100"

    strings:
        $ = "<!DOCTYPE" ascii wide
        $ = "<html>" ascii wide
        $ = "<title>" ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}
import "pe"

rule INFO_PE_Contains_404_Title
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to a 404 response page"
        DaysofYARA = "16/100"

    strings:
        $ = "<title>404" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_Contains_HTML_Page
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to HTML"
        DaysofYARA = "16/100"

    strings:
        $ = "<!DOCTYPE" ascii wide
        $ = "<html>" ascii wide
        $ = "<title>" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_Contains_NotFound
{
    strings:
        $ = "not found.<" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_ELF_Contains_404_Title
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to a 404 response page"
        DaysofYARA = "16/100"

    strings:
        $ = "<title>404" ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_PE_WSARecv_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference WSARecv, which may be hooked for passive listening"
        DaysofYARA = "17/100"

    strings:
        $ = "WSARecv" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_DeviceIOControl_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference DeviceIOControl, which may be hooked for passive listening"
        DaysofYARA = "17/100"

    strings:
        $ = "DeviceIOControl" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

//rule INFO_PE_HttpInitialize_API
//{
//    meta:
//        author = "Greg Lesnewich"
//        date = "2024-01-17"
//        version = "1.0"
//        description = "track executable files that reference HttpInitialize, which may be hooked for passive listening"
//        DaysofYARA = "17/100"
//
//    strings:
//        $ = "HttpInitialize" nocase ascii wide
//    condition:
//        uint16be(0) == 0x4d5a and all of them
//}

rule INFO_PE_HttpReceiveHttpRequest_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpReceiveHttpRequest, which will be used to handle inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpReceiveHttpRequest" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}


rule INFO_PE_HttpSendHttpResponse_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpSendHttpResponse, which will be used to respond to inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpSendHttpResponse" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_HttpSendResponseEntityBody_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpSendResponseEntityBody, which will be used to respond to inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpSendResponseEntityBody" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}




rule INFO_PE_Port_Slash_Combo
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that include small strings that might indicate port usage "
        DaysofYARA = "17/100"

    strings:
        $ = ":80/" ascii wide
        $ = ":443/" ascii wide
        $regex = /\:[0-9]{2,4}\//ascii wide
    condition:
        uint16be(0) == 0x4d5a and any of them
}


rule INFO_PE_WebServer_References_Apache
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the Apache web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "Apache" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}
rule INFO_PE_WebServer_References_Microsoft_IIS
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the Microsoft-IIS web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "Microsoft-IIS" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}
rule INFO_PE_WebServer_References_OpenResty
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the OpenResty web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "OpenResty" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}
rule INFO_PE_WebServer_References_nginx
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the nginx web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "nginx" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_WebServer_References_LiteSpeed
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the LiteSpeed web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "LiteSpeed" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}


rule INFO_PE_Imports_NDIS_NetworkInterface
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-20"
        version = "1.0"
        description = "track executable files that import NDIS which is a legitimate driver for the network interface controller."
        DaysofYARA = "20/100"

    condition:
        for any imp in pe.import_details:(
            imp.library_name == "NDIS.SYS"
            )
}

rule INFO_PE_Imports_HardwareAbstractionLayer
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-20"
        version = "1.0"
        description = "track executable files that import hardware abstraction layer (HAL) components"
        DaysofYARA = "20/100"

    condition:
        for any s in ("hal.dll","halacpi.dll","halmacpi.dll"):(
            for any imp in pe.import_details:(
                imp.library_name iequals s
        ))
}
rule INFO_LNK_File_Ref_wsf {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .wsf"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".wsf" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_js {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .js"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".js" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_hta {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .hta"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".hta" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_vbscript {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference vbscript"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "vbscript" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_javascript {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference javascript"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "javascript" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_7z {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference 7z"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "7z" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_java {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference java"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "java" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_py {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .py"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".py" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_certutil {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference certutil"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "certutil" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_msbuild {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference msbuild"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "msbuild" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_curl {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference curl"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "curl" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_regsvr {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference regsvr"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "regsvr" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_scriptrunner {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference scriptrunner"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "scriptrunner" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_registerocx {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference registerocx"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "registerocx" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_advpackdll {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference advpack.dll"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "advpack.dll" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_shellexec {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference shellexec"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "shellexec" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_set {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference set"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "set" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_exit {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference exit"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "exit" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_copy {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference copy"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "copy" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_xcopy {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference xcopy"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "xcopy" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_echo {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference echo"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "echo" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_findstr {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference findstr"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "findstr" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_call {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference call"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "call" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_attrib {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference attrib"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "attrib" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_cls {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference cls"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "cls" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_rem {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference rem"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "rem" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_goto {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference goto"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "goto" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_msg {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference msg"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "msg" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_app {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference --app="
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "--app=" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_package {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference -package"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "-package" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_getcontent {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference get-content"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "get-content" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_odbcconf {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference odbcconf"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "odbcconf" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_rsp {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .rsp"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".rsp" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_sleep {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference sleep"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "sleep" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_taskkill {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference taskkill"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "taskkill" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_pcalua {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference pcalua"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "pcalua" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_expand {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference expand"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "expand" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_conhost {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference conhost"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "conhost" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_mount {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference mount"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "mount" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_unblock_file {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference unblock-file"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "unblock-file" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_expand_archive {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference expand-archive"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "expand-archive" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}
rule INFO_LNK_References_WildCard_LNK_FileHandle
{
    meta:
        author = "Greg Lesnewich"
        description = "identify LNK files that might look for themselves, by referencing a wildcarded LNK filename"
        date = "2024-01-30"
        version = "1.0"
        DaysOfYara = "30/100"

    strings:
        $ = "*.lnk" ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_SelfParsing_Findstr_LNK_FileHandle
{
    meta:
        author = "Greg Lesnewich"
        description = "identify LNK files that likely parse themselves looking for additional files or commands"
        date = "2024-01-30"
        version = "1.0"
        DaysOfYara = "30/100"

    strings:
        $ = ".lnk" ascii wide
        $ = "findstr" ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}
rule INFO_Macho_ExternalLibary_Load_Count_0
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 0

}


rule INFO_Macho_ExternalLibary_Load_Count_1
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 1

}


rule INFO_Macho_ExternalLibary_Load_Count_2
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 2

}


rule INFO_Macho_ExternalLibary_Load_Count_3
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 3

}

rule INFO_Macho_ExternalLibary_Load_Count_4
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 4

}

rule INFO_Macho_ExternalLibary_Load_Count_5
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 5

}

rule INFO_Macho_ExternalLibary_Load_Count_More_Than_5
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) > 5

}
rule INFO_Macho_Has_CodeSignature
{
    meta:
        author = "Greg Lesnewich"
        description = "check Macho files for an LC_CODE_SIGNATURE load command"
        date = "2023-01-29"
        version = "1.0"

condition:
	(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	for any cs_sig in (0 .. 0x1000) : (
			uint32be(cs_sig) == 0x1D000000
		)
}
rule INFO_Macho_LoadCommands_Less_Than_10
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
		description = "check for Macho files with less than 10 load commands"
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		uint32(0x10) <= 0x0a
}
rule INFO_Macho_Long_RPATH
{
	meta:
		author = "Greg Lesnewich"
		description = "check for Macho's that contain an RPath load command, where the data size is larger than 30 bytes"
		date = "2024-01-02"
		version = "1.0"
		DaysofYARA = "2/100"
		reference = "https://securelist.com/trojan-proxy-for-macos/111325/"

	strings:
		$rpath = {1c 00 00 80}
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and filesize < 10MB and
			$rpath in (0..2000) and uint16(@rpath + 4) >= 30
}
rule INFO_Macho_LOObin_csrutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin csrutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "csrutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}


rule INFO_Macho_LOObin_ditto {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin ditto"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "ditto" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_dnssd {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin dns"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "dns-sd" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_dscl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin dscl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "dscl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
}

rule INFO_Macho_LOObin_dsexport {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin dsexport"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "dsexport" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_GetFileInfo {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin GetFileInfo"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "GetFileInfo" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_hdiutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin hdiutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "hdiutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_ioreg {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin ioreg"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "ioreg" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_lsregister {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin lsregister"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "lsregister" ascii wide

	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_mdfind {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin mdfind"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "mdfind" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_networksetup {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin networksetup"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "networksetup" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_nscurl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin nscurl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "nscurl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_nvram {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin nvram"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "nvram" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}


rule INFO_Macho_LOObin_osacompile {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin osacompile"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "osacompile" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_osascript {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin osascript"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "osascript" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_pbpaste {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin pbpaste"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "pbpaste" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_plutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin plutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "plutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_profiles {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin profiles"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "profiles" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_safaridriver {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin safaridriver"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "safaridriver" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_screencapture {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin screencapture"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "screencapture" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_SetFile {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin SetFile"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "SetFile" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_softwareupdate {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin softwareupdate"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "softwareupdate" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_spctl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin spctl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "spctl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_sqlite3 {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin sqlite3"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "sqlite3" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_sshkeygen {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin ssh"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "ssh-keygen" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_sysctl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin sysctl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "sysctl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_tclsh {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin tclsh"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "tclsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_textutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin textutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "textutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_tmutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin tmutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "tmutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_xattr {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin xattr"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "xattr" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}
rule INFO_Macho_LowLevel_API_task_info
{
    meta:
        description = "check Macho files for low level API of task_info, used by _xpn_ to get dydl in memory base address"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "task_info" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

rule INFO_Macho_LowLevel_Dydl_API_mmap
{
    meta:
        description = "check Macho files for low level API of mmap to map a file into memory"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "mmap" ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

rule INFO_Macho_LowLevel_Dydl_API_pread
{
    meta:
        description = "check Macho files for low level API of pread to read from a given input"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "pread" ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

rule INFO_Macho_LowLevel_Dydl_API_fcntl
{
    meta:
        description = "check Macho files for low level API of fcntl which is used to control open files and provides for control over descriptors"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "fcntl" ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}
rule INFO_Macho_Multiple_Init_Funcs
{
    meta:
        	author = "Greg Lesnewich"
        	description = "check Macho files for multiple initialization methods, via presence of a Mod Init Func section"
        	date = "2023-01-26"
        	version = "1.0"
	strings:
		$section = "mod_init_func" ascii wide
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	all of them
}
rule INFO_Macho_Hunting_Osascript
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for potential scripting interfaces like osascript"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"

	strings:
		$ = "osascript" nocase ascii wide
		$ = "osacompile" nocase ascii wide
		$ = ".scpt" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and any of them
}

rule INFO_Macho_Hunting_AppleScript_URL
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for potential scripting interfaces like AppleScript"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"

	strings:
		$ = "applescript://" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and any of them
}


rule INFO_Macho_Hunting_Python
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for additional execution strings like python"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"

	strings:
		$str = "python" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}
rule INFO_Macho_Hunting_Ruby
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for additional execution strings like Ruby"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$str = "Ruby" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}
rule INFO_Macho_Hunting_Perl
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for additional execution strings like perl"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$str = "perl" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}



rule INFO_Macho_Execution_BinBash
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like bash shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/bash" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		)
		and all of them
}

rule INFO_Macho_Execution_Bin_sh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like sh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/sh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}

rule INFO_Macho_Execution_BinZsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like zsh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/zsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}


rule INFO_Macho_Execution_Bin_tcsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like tcsh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/tcsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}


rule INFO_Macho_Execution_BinKsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like ksh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/ksh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}

rule INFO_Macho_Execution_Bincsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like csh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/csh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}

rule INFO_Macho_Execution_tclsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like tclsh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "usr/bin/tclsh" ascii wide
		$ = "bin/tclsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}
rule INFO_MacOS_NamedPipe_mkfifo
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for mkfifo command used to create a MacOS named pipe"

	strings:
		$ = "mkfifo" ascii wide
	condition:
		all of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSXPC
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for references to XPC, MacOS low-level interprocess communications, via the NSXPCConnection API classes"

	strings:
		$ = "NSXPCConnection" ascii wide
		$ = "NSXPCInterface" ascii wide
		$ = "NSXPCListener" ascii wide
		$ = "NSXPCListenerEndpoint" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_XPC_API
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for references to XPC, MacOS low-level interprocess communications, via the XPC APIs"

	strings:
		$ = "IOSurfaceLookupFromXPCObject" ascii wide
		$ = "IOSurfaceCreateXPCObject" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSPipe
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for ObjectiveC interface NSPipe"

	strings:
		$ = "$_NSPipe" ascii wide
		$ = "NSPipe" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSConnection
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for deprecated ObjectiveC interface NSConnection, used in distributed objects mechanism, often to vend an object to other applications"

	strings:
		$ = "NSConnection" ascii wide
	condition:
		any of them
}
rule INFO_PList_Param_StartInterval { strings: $ = "<key>StartInterval</key>" ascii wide condition: all of them }
rule INFO_PList_Param_ThrottleInterval { strings: $ = "<key>ThrottleInterval</key>" ascii wide condition: all of them }
rule INFO_PList_Param_AbandonProcessGroup { strings: $ = "<key>AbandonProcessGroup</key>" ascii wide condition: all of them }
rule INFO_PList_Param_RootDirectory { strings: $ = "<key>RootDirectory</key>" ascii wide condition: all of them }
rule INFO_PList_Param_Umask { strings: $ = "<key>Umask</key>" ascii wide condition: all of them }
rule INFO_PList_Param_OtherJobEnabled { strings: $ = "<key>OtherJobEnabled</key>" ascii wide condition: all of them }
rule INFO_PList_Param_QueueDirectories { strings: $ = "<key>QueueDirectories</key>" ascii wide condition: all of them }
rule INFO_PList_Param_WatchPaths { strings: $ = "<key>WatchPaths</key>" ascii wide condition: all of them }
rule INFO_PList_Param_StartCalendarInterval { strings: $ = "<key>StartCalendarInterval</key>" ascii wide condition: all of them }
rule INFO_PList_Param_StartOnMount { strings: $ = "<key>StartOnMount</key>" ascii wide condition: all of them }
rule INFO_PList_Param_EnvironmentVariables { strings: $ = "<key>EnvironmentVariables</key>" ascii wide condition: all of them }
rule INFO_PList_Param_ProgramArguments { strings: $ = "<key>ProgramArguments</key>" ascii wide condition: all of them }

rule SUSP_PList_Param_RunAtLoad { strings: $ = "<key>RunAtLoad</key>" ascii wide condition: all of them }
rule SUSP_PList_Param_KeepAlive { strings: $ = "<key>KeepAlive</key>" ascii wide condition: all of them }

rule SUSP_PList_Param_RunAtLoad_base64 { strings: $ = "<key>RunAtLoad</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_KeepAlive_base64 { strings: $ = "<key>KeepAlive</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_StartInterval_base64 { strings: $ = "<key>StartInterval</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_ThrottleInterval_base64 { strings: $ = "<key>ThrottleInterval</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_AbandonProcessGroup_base64 { strings: $ = "<key>AbandonProcessGroup</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_RootDirectory_base64 { strings: $ = "<key>RootDirectory</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_Umask_base64 { strings: $ = "<key>Umask</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_OtherJobEnabled_base64 { strings: $ = "<key>OtherJobEnabled</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_QueueDirectories_base64 { strings: $ = "<key>QueueDirectories</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_WatchPaths_base64 { strings: $ = "<key>WatchPaths</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_StartCalendarInterval_base64 { strings: $ = "<key>StartCalendarInterval</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_StartOnMount_base64 { strings: $ = "<key>StartOnMount</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_EnvironmentVariables_base64 { strings: $ = "<key>EnvironmentVariables</key>" base64 base64wide condition: all of them }
rule SUSP_PList_Param_ProgramArguments_base64 { strings: $ = "<key>ProgramArguments</key>" base64 base64wide condition: all of them }

rule SUSP_PList_Param_RunAtLoad_xor { strings: $ = "<key>RunAtLoad</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_KeepAlive_xor { strings: $ = "<key>KeepAlive</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_StartInterval_xor { strings: $ = "<key>StartInterval</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_ThrottleInterval_xor { strings: $ = "<key>ThrottleInterval</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_AbandonProcessGroup_xor { strings: $ = "<key>AbandonProcessGroup</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_RootDirectory_xor { strings: $ = "<key>RootDirectory</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_Umask_xor { strings: $ = "<key>Umask</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_OtherJobEnabled_xor { strings: $ = "<key>OtherJobEnabled</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_QueueDirectories_xor { strings: $ = "<key>QueueDirectories</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_WatchPaths_xor { strings: $ = "<key>WatchPaths</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_StartCalendarInterval_xor { strings: $ = "<key>StartCalendarInterval</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_StartOnMount_xor { strings: $ = "<key>StartOnMount</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_EnvironmentVariables_xor { strings: $ = "<key>EnvironmentVariables</key>" xor(0x01-0xff) condition: all of them }
rule SUSP_PList_Param_ProgramArguments_xor { strings: $ = "<key>ProgramArguments</key>" xor(0x01-0xff) condition: all of them }
import "console"
rule Logger_Macho_EntryPoint_LCMain
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from LCMain / MAIN_DYLIB load commands"
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	for any LCMain in (0 .. 0x1000) : (
            	uint32be(LCMain) == 0x28000080 and console.log("LCMain_entry_point_hash: ", hash.md5(uint32(LCMain+8), 16))
        )
}

rule Logger_Macho_EntryPoint_UnixThread_32Bit
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from UnixThread load commands"
    condition:
        uint32be(0x0) == 0xCEFAEDFE and
		for any unix_Thread in (0 .. 0x1000) : (
                	uint32be(unix_Thread) == 0x05000000 and
			uint32be(unix_Thread+8) == 0x01000000
			and console.hex("unix_Thread_x32_entry_point_hash: ", uint32(unix_Thread+0x38))
        )
}

rule Logger_Macho_EntryPoint_UnixThread_64Bit
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from UnixThread load commands"
    condition:
        uint32be(0x0) == 0xCFFAEDFE
		and for any unix_Thread in (0 .. 0x1000) : (
                	uint32be(unix_Thread) == 0x05000000 and
			uint32be(unix_Thread+8) == 0x04000000
			and console.hex("unix_Thread_entry_point_64: ", (uint32(unix_Thread+0x90)) + 0x100000000)
                )
}
rule MAL_GOLDBACKDOOR_LNK
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
		DaysofYARA = "2/100"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$doc_icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide
		$script_apionedrivecom_hex_enc_str = "6170692e6f6e6564726976652e636f6d" wide
		$script_kernel32dll_hex_enc_str = "6b65726e656c33322e646c6c" wide
		$script_GlobalAlloc_hex_enc_str = "476c6f62616c416c6c6f63" wide
		$script_VirtualProtect_hex_enc_str = "5669727475616c50726f74656374" wide
		$script_WriteByte_hex_enc_str = "577269746542797465" wide
		$script_CreateThread_hex_enc_str = "437265617465546872656164" wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of ($doc*) and
		2 of ($script*)
}
rule MAL_MATA_SendPacket_Command_Opcodes
{
		meta:
			author = "Greg Lesnewich"
			date = "2023-01-18"
			version = "1.0"
			description = "check for Mata framework packet opcodes being moved into EDI before sending"

		strings:
			$0x20300 = { bf 00 03 02 00 31 f6 31 d2 e8 }
			$0x20600 = { bf 00 06 02 00 31 f6 49 89 d5 31 d2 e8 }
			$0x20500 = { bf 00 05 02 00 31 f6 31 d2 e8 }
			/*
				100005d7b  bf00050200         mov     edi, 0x20500
				100005d80  31f6               xor     esi, esi  {0x0}
				100005d82  31d2               xor     edx, edx  {0x0}
				100005d84  e867f9ffff         call    MataSendPacket
			*/
		condition:
			(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
			all of them
}


rule MAL_MATA_Beacon_Command_Opcodes
{
		meta:
			author = "Greg Lesnewich"
			date = "2023-01-18"
			version = "1.0"
			description = "check for Mata framework beacon opcodes and handshake check"

		strings:
			$CMataNet_Auth = {
			c745c400000200     //1000012a2  c745c400000200     mov     dword [rbp-0x3c {var_44}], 0x20000
			488d75c4           //1000012a9  488d75c4           lea     rsi, [rbp-0x3c {var_44}]
			4c89f7             //1000012ad  4c89f7             mov     rdi, r14
			ba04000000         //1000012b0  ba04000000         mov     edx, 0x4
			b901000000         //1000012b5  b901000000         mov     ecx, 0x1
			e8????????         //1000012ba  e8????????         call    CMataNet_SendBlock
			85c0               //1000012bf  85c0               test    eax, eax
			74??               //1000012c1  74??               je      0x10000131b
			c745c400000000     //1000012c3  c745c400000000     mov     dword [rbp-0x3c {var_44}], 0x0
			488d75c4           //1000012ca  488d75c4           lea     rsi, [rbp-0x3c {var_44}]
			4c89f7             //1000012ce  4c89f7             mov     rdi, r14
			ba04000000         //1000012d1  ba04000000         mov     edx, 0x4
			b901000000         //1000012d6  b901000000         mov     ecx, 0x1
			41b82c010000       //1000012db  41b82c010000       mov     r8d, 0x12c
			e8????????         //1000012e1  e8????????         call    CMataNet_RecvBlock
			4531e4             //1000012e6  4531e4             xor     r12d, r12d  {0x0}
			85c0               //1000012e9  85c0               test    eax, eax
			74??               //1000012eb  74??               je      0x10000131e
			817dc400010200     //1000012ed  817dc400010200     cmp     dword [rbp-0x3c {var_44}], 0x20100
			75??   						 //1000012f4  75??               jne     0x10000131e
			c745c400020200     //1000012f6  c745c400020200     mov     dword [rbp-0x3c {var_44}], 0x20200
		}

		condition:
			(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
			all of them
}
rule MAL_PuzzleMaker_Launcher
{
    meta:
        description = "track the PuzzleMaker launcher based on its call to interact with the WMI namespace (CLSID_WbemLocator via CoCreateInstance)"
        author = "Greg Lesnewich"
        date = "2023-01-13"
        version = "1.0"
        reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
        hash = "982f7c4700c75b81833d5d59ad29147c392b20c760fe36b200b541a0f841c8a9"
        hash = "44d9f36c088dd420ad96a8518df7e9155145e04db788a99a8f8f99179427a447"
        hash = "bab8ad15015589e3f70643e6b59a5a37ab2c5a9cf799e0472cb9c1a29186babc"

    strings:
	$call_CoCreateInstance_WbemLocator = { 4? 89 6d bf 4? 8d 45 bf 4? 89 44 ?4 20 4? 8d 0d ?? ?? ?? ?? 33 d2 44 8d 42 01 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d8 85 c0  }
        /*
           140001e9b  MOV        qword ptr [RBP + local_a0],R13
           140001e9f  LEA        RAX=>local_a0,[RBP + -0x41]
           140001ea3  MOV        qword ptr [RSP + local_e8],RAX
           140001ea8  LEA        R9,[DAT_1400164a8]                               = 87h
           140001eaf  XOR        param_2,param_2
           140001eb1  LEA        R8D,[param_2 + 0x1]
           140001eb5  LEA        param_1,[CLSID_WbemLocator]                      = 11
           140001ebc  CALL       qword ptr [->OLE32.DLL::CoCreateInstance]

        */
        $CreateService = { 4? 89 6c ?4 60 4? 8d 05 ?? ?? ?? ?? 4? 89 6c ?4 58 4? 8d 15 ?? ?? ?? ?? 4? 89 6c ?4 50 41 b9 ff 01 0f 00 4? 89 6c ?4 48 4? 8b cf 4? 89 6c ?4 40 4? 89 74 ?4 38 44 89 6c ?4 30 c7 44 ?4 28 02 00 00 00 c7 44 ?4 20 10 00 00 00 ff 15 }
        /*
           14000199f 4c 89 6c      MOV        qword ptr [RSP + local_5f8],R13
           1400019a4 4c 8d 05      LEA        R8,[DAT_14001e5d0]                               = 20h
           1400019ab 4c 89 6c      MOV        qword ptr [RSP + local_600],R13
           1400019b0 48 8d 15      LEA        RDX,[DAT_140021e98]                              = 0095h
           1400019b7 4c 89 6c      MOV        qword ptr [RSP + local_608],R13
           1400019bc 41 b9 ff      MOV        R9D,0xf01ff
           1400019c2 4c 89 6c      MOV        qword ptr [RSP + local_610],R13
           1400019c7 48 8b cf      MOV        RCX,RDI
           1400019ca 4c 89 6c      MOV        qword ptr [RSP + local_618],R13
           1400019cf 48 89 74      MOV        qword ptr [RSP + local_620],RSI=>DAT_140021c90   = 00A1h
           1400019d4 44 89 6c      MOV        dword ptr [RSP + local_628],R13D
           1400019d9 c7 44 24      MOV        dword ptr [RSP + local_630],0x2
           1400019e1 c7 44 24      MOV        dword ptr [RSP + local_638],0x10
           1400019e9 ff 15 19      CALL       qword ptr [->ADVAPI32.DLL::CreateServiceW]

        */
    condition:
        uint16be(0x0) == 0x4d5a and
        1 of them
}


rule MAL_PuzzleMaker_Payload
{
    meta:
        description = "track the PuzzleMaker payload based on some cryptography API calls and a subroutine in a case (maybe a command?) statement"
        author = "Greg Lesnewich"
        date = "2023-01-13"
        version = "1.0"
        reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
        hash = "2ae29e697c516dc79c6fbf68f951a5f592f151abd81ed943c2fdd225c5d4d391"
        hash = "8a17279ba26c8fbe6966ea3300fdefb1adae1b3ed68f76a7fc81413bd8c1a5f6"
        hash = "f2ce2a00de8673f52d37911f3e0752b8dfab751b2a17e719a565b4083455528e"

    strings:
        $case_statement = { 33 db 4? 8d 4? ?? 80 7? 00 01 8b fb 41 8b d4 4? 8b ce 40 0f 94 ?? 41 80 f9 15 89 7c ?4 20 0f 94 ?? 44 8b cb  }
        /*
            switchD_180001fd4::caseD_15
           180001fe7  XOR        EBX,EBX
           180001fe9  LEA        R8,[RBP + 0x1]
           180001fed  CMP        byte ptr [RBP],0x1
           180001ff1  MOV        EDI,EBX
           180001ff3  MOV        param_2,R12D
           180001ff6  MOV        param_1,RSI
           180001ff9  SETZ       DIL
           180001ffd  CMP        R9B,0x15
           180002001  MOV        dword ptr [RSP + local_f8],EDI
           180002005  SETZ       BL
           180002008  MOV        R9D,EBX
           18000200b  CALL       mw_open_pipe_create_proc                         undefined mw_open_pipe_create_pr

        */

        $cryptography = { 41 b9 01 00 00 00 c7 44 ?4 20 00 00 00 f0 45 33 c0 4? 8d 4c ?4 60 33 d2 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 4? 8b 4c ?4 60 4? 8d 85 b0 00 00 00 ba 20 00 00 00 ff 15 ?? ?? ?? ?? 4? 8b 4c ?4 60 33 d2  }
        /*
           1800040d1  MOV        R9D,0x1
           1800040d7  MOV        dword ptr [RSP + local_9e8],0xf0000000
           1800040df  XOR        param_3,param_3
           1800040e2  LEA        param_1=>local_9b8,[RSP + 0x50]
           1800040e7  XOR        param_2,param_2
           1800040e9  CALL       qword ptr [->ADVAPI32.DLL::CryptAcquireContextW]
           1800040ef  TEST       EAX,EAX
           1800040f1  JZ         LAB_18000411b
           1800040f3  MOV        param_1=>local_9b8,qword ptr [RSP + 0x50]
           1800040f8  LEA        param_3=>local_868,[RBP + 0xa0]
           1800040ff  MOV        param_2,0x20
           180004104  CALL       qword ptr [->ADVAPI32.DLL::CryptGenRandom]
           18000410a  MOV        param_1,qword ptr [RSP + local_9b8]
           18000410f  XOR        param_2,param_2
           180004111  TEST       EAX,EAX
           180004113  JNZ        LAB_180004125
           180004115  CALL       qword ptr [->ADVAPI32.DLL::CryptReleaseContext]

        */

    condition:
        uint16be(0x0) == 0x4d5a and
        1 of them
}
import "pe"

rule MAL_Zardoor_Export_MainEntry {

    meta:
        description = "track a consistent export function in combination with tool version info, used by the Zardoor dropper and its embedded backdoor tools"
        author = "Greg Lesnewich"
        date = "2024-02-11"
        version = "1.0"
        reference = "https://blog.talosintelligence.com/new-zardoor-backdoor/"
        DaysOfYara = "42/100"
        hash = "0058d495254bf3760b30b5950d646f9a38506cef8f297c49c3b73c208ab723bf"
        hash = "a99a9f2853ff0ca5b91767096c7f7e977b43e62dd93bde6d79e3407bc01f661d"
        hash = "d267e2a6311fe4e2dfd0237652223add300b9a5233b555e131325a2612e1d7ef"

    condition:
        pe.exports("MainEntry")
        and pe.rich_signature.toolid(241,40116) // C++ Libary UTC1810_CPP from Visual Studio 2013 12.10"
        and pe.rich_signature.toolid(243,40116) // C++ Libary UTC1810_CPP from Visual Studio 2013 12.10"
        and pe.rich_signature.toolid(242,40116) // C++ Libary UTC1810_CPP from Visual Studio 2013 12.10"
        and pe.rich_signature.toolid(259,24123) // C Libary UTC1900_CPP from Visual Studio 2015 14.0.3 RC
        and pe.rich_signature.toolid(261,24123) // C Libary UTC1900_CPP from Visual Studio 2015 14.0.3 RC
        and pe.rich_signature.toolid(260,24123) // C Libary UTC1900_CPP from Visual Studio 2015 14.0.3 RC
        and pe.rich_signature.toolid(147,30729) // Import Library IMPLIB900 from Visual Studio 2008 9.0
        and pe.rich_signature.toolid(1,0) // Visual Studio Resource
        and pe.rich_signature.toolid(265,24215) // Linker from Visual Studio 2008 9.0
        and pe.rich_signature.toolid(256,24215) // Linker from Visual Studio 2008 9.0
        and pe.rich_signature.toolid(255,24210) // CVTRES1400 from Visual Studio 2015 14.0.3
        and pe.rich_signature.toolid(258,24215) // Linker from Visual Studio 2008 9.0
}


rule MAL_Zardoor_Dropper_Resource_TypeString_CODER
{
    meta:
        author = "Greg Lesnewich"
        description = "look for weird typestring included in Zardoor loader called CODER"
        date = "2024-02-12"
        version = "1.0"
        reference = "https://blog.talosintelligence.com/new-zardoor-backdoor/"
        DaysOfYara = "43/100"
        hash = "a99a9f2853ff0ca5b91767096c7f7e977b43e62dd93bde6d79e3407bc01f661d"

    condition:
        for any rsrc in pe.resources:
            (rsrc.type_string == "C\x00O\x00D\x00E\x00R\x00") //CODER
}
rule SUSP_Base64_String_in_base64
{
    meta:
        author = "Greg Lesnewich"
        description = "look for the string base64, encoded in base64, which just seems odd"
        date = "2024-02-06"
        version = "1.0"
        DaysOfYara = "37/100"

    strings:
        $ = "base64" base64 base64wide
    condition:
        all of them
}
rule SUSP_Bloated_LNK
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files with a size over 250KB - examples from Janicab (PDF) and GOLDBACKDOOR (Doc) and MustangPanda (HTML)"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "2/100"

	condition:
		uint32be(0x0) == 0x4C000000 and
		filesize > 250KB
}
import "pe"
rule SUSP_DLL_All_LowerCase_Exports
{
	meta:
		author = "Greg Lesnewich"
		description = "track weird PE's that do not contain any capital letters in their export names, inspired by the CoreLump, MataDoor L-Library Loader, and BruteRatel families"
		date = "2024-01-13"
		version = "1.0"
		hash = "c96ae21b4cf2e28eec222cfe6ca903c4767a068630a73eca58424f9a975c6b7d" // CoreLump
		hash = "8c94a3cef4e45a1db05ae9723ce5f5ed66fc57316e9868f66c995ebee55f5117" // MataDoor L-Library_Loader
		DaysofYARA = "13/100"

	condition:
		for all exps in pe.export_details: (
			for all letter in ("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"):
			(
				not exps.name contains letter
			)
		)
}
import "pe"
rule SUSP_DLL_Duplicated_First_ExportNames
{
	meta:
		author = "Greg Lesnewich"
		description = "track a weird TTP abused by DPRK operators, where a trojanized binary will use a duplicated or incremented export name"
		date = "2024-01-04"
		version = "1.0"
		DaysOfYara = "6/100"
		hash = "c8707d9d7f3ade7f8aa25034e6a73060e5998db980e90452eb0190994036d781" // DRATzarus
		hash = "26a2fa7b45a455c311fd57875d8231c853ea4399be7b9344f2136030b2edc4aa" // DTrack
		hash = "ec254c40abff00b104a949f07b7b64235fc395ecb9311eb4020c1c4da0e6b5c4" // Deathnote
		hash = "722fa0c893b39fef787b7bc277c979d29adc1525d77dd952f0cc61cd4d0597cc" // FP, Turla RPCBackdoor
		hash = "84b5a89917792291e2425b64e093580ca8d2e106532e433e949cdde3c2db4053" // Klackring
		hash = "39ad9ae3780c2f6d41b1897e78f2b2b6d549365f5f024bc68d1fe794b940f9f1" // ThreatNeedle

	condition:
		pe.number_of_exports < 5 and
		(
			((pe.export_details[1].name startswith pe.export_details[0].name) and
			pe.export_details[1].name endswith "W") or

			((pe.export_details[2].name startswith pe.export_details[0].name) and
			pe.export_details[2].name endswith "W") or

			((pe.export_details[2].name startswith pe.export_details[1].name) and
			pe.export_details[2].name endswith "W")
		)

}
import "dotnet"

rule SUSP_DotNet_Method_Param_Payload
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-06"
        version = "1.0"
        DaysofYARA = "6/100"
    condition:
    for any item in dotnet.classes: (
        for any methy in item.methods: (
            for any param in methy.parameters: (
                param.name icontains "payload"
            )
        )
    )

}


rule SUSP_DotNet_Method_Param_Key
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-06"
        version = "1.0"
        DaysofYARA = "6/100"
    condition:
    for any item in dotnet.classes: (
        for any methy in item.methods: (
            for any param in methy.parameters: (
                param.name icontains "key"
            )
        )
    )

}


rule SUSP_DotNet_Method_Param_HTTP
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-06"
        version = "1.0"
        DaysofYARA = "6/100"


    condition:
    for any item in dotnet.classes: (
        for any methy in item.methods: (
            for any param in methy.parameters: (
                param.name icontains "http"
            )
        )
    )

}
import "pe"

rule SUSP_Export_Offset_Zero
{
    meta:
        author = "Greg Lesnewich"
        description = "check for files that have at least 1 export that has an offset of 0"
        date = "2023-01-14"
        version = "1.0"
        DaysofYARA = "14/100"

    condition:
        for any exp in pe.export_details: (
            exp.offset == 0 and
            not defined exp.name  and
            not defined exp.forward_name
        )
}


rule SUSP_Export_Offset_Undefined
{
    meta:
        author = "Greg Lesnewich"
        description = "check for files that have at least 1 export that has an no defined offset or other fields"
        date = "2023-01-14"
        version = "1.0"
        DaysofYARA = "14/100"

    condition:
        for any exp in pe.export_details: (
            not defined exp.offset and
            not defined exp.name  and
            not defined exp.forward_name
        )
}

rule SUSP_kernel32_mutation_b64 
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_b64 = "kernel32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_xor = "kernel32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_flipflop
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_flipflop = "eknrle23" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_flipflop_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_flipflop_b64 = "eknrle23" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_flipflop_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_flipflop_xor = "eknrle23" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_rot13
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_rot13 = "xreary32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_rot13_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_rot13_b64 = "xreary32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_rot13_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_rot13_xor = "xreary32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_reverse
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_reverse = "23lenrek" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_reverse_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_reverse_b64 = "23lenrek" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_reverse_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_reverse_xor = "23lenrek" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str = "6b65726e656c3332" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64 = "6b65726e656c3332" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_xor = "6b65726e656c3332" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_spaces
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_spaces = "6b 65 72 6e 65 6c 33 32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_spaces_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_spaces_b64 = "6b 65 72 6e 65 6c 33 32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_spaces_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_spaces_xor = "6b 65 72 6e 65 6c 33 32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_commas
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_commas = "6b,65,72,6e,65,6c,33,32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_commas_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_commas_b64 = "6b,65,72,6e,65,6c,33,32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_commas_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_commas_xor = "6b,65,72,6e,65,6c,33,32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_double_hex_enc_str
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_double_hex_enc_str = "36623635373236653635366333333332" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_double_hex_enc_str_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_double_hex_enc_str_b64 = "36623635373236653635366333333332" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_double_hex_enc_str_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_double_hex_enc_str_xor = "36623635373236653635366333333332" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64_enc_str = "NmI2NTcyNmU2NTZjMzMzMg==" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64_enc_str_b64 = "NmI2NTcyNmU2NTZjMzMzMg==" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64_enc_str_xor = "NmI2NTcyNmU2NTZjMzMzMg==" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_reversed
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_reversed = "2333c656e62756b6" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_reversed_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_reversed_b64 = "2333c656e62756b6" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_reversed_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_reversed_xor = "2333c656e62756b6" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal = "107 101 114 110 101 108 51 50" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_b64 = "107 101 114 110 101 108 51 50" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_xor = "107 101 114 110 101 108 51 50" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_commas
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_commas = "107,101,114,110,101,108,51,50" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_commas_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_commas_b64 = "107,101,114,110,101,108,51,50" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_commas_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_commas_xor = "107,101,114,110,101,108,51,50" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_fallchill
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_fallchill = "pvimvo32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_fallchill_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_fallchill_b64 = "pvimvo32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_fallchill_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_fallchill_xor = "pvimvo32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpush
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpush = "hel32hkern" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpush_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpush_b64 = "hel32hkern" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpush_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpush_xor = "hel32hkern" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpushnull
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpushnull = "hel32\x00hkern"
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpushdoublenull
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpushdoublenull = "hel32\x00\x00hkern"
	condition:
		all of them
}
rule SUSP_LNK_Abnormal_CLSID_Not_MyComputer
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-04"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "4/100"

	strings:
		$clsid = {E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D}
	condition:
		uint32be(0x0) == 0x4C000000 and none of them
}
rule SUSP_LNK_Contains_Padding
{
	meta:
		author = "Greg Lesnewich"
		description = "Look for LNK files with space padded commandline args"
		date = "2023-01-05"
		version = "1.0"
		DaysofYARA = "5/100"

	strings:
		$padding = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 }
	condition:
		uint32be(0x0) == 0x4c000000 and $padding
}
rule SUSP_LNK_Contains_PE_DOS_Stub
{
    meta:
        author = "Greg Lesnewich"
        description = "detect LNKs that contain an MS-DOS stub indicating there is likely an embedded PE file"
        reference = "https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/"
        date = "2024-02-03"
        version = "1.0"
        DaysOfYara = "34/100"
    strings:
        $ = "!This program cannot be run in DOS mode" nocase ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and
        1 of them
}

rule SUSP_LNK_Contains_PE_DOS_Stub_b64
{
    meta:
        author = "Greg Lesnewich"
        description = "detect LNKs that contain an MS-DOS stub indicating there is likely an embedded PE file"
        reference = "https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/"
        date = "2024-02-03"
        version = "1.0"
        DaysOfYara = "34/100"
    strings:
        $ = "!This program cannot be run in DOS mode" base64 base64wide
        $ = "!This Program Cannot be Run in DOS Mode" base64 base64wide
    condition:
        uint32be(0x0) == 0x4c000000 and
        1 of them
}

rule SUSP_LNK_Contains_PE_DOS_Stub_xor
{
    meta:
        author = "Greg Lesnewich"
        description = "detect LNKs that contain an MS-DOS stub indicating there is likely an embedded PE file"
        reference = "https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/"
        date = "2024-02-03"
        version = "1.0"
        DaysOfYara = "34/100"
    strings:
        $ = "!This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
        $ = "!This Program Cannot be Run in DOS Mode" xor(0x01-0xff) ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and
        1 of them
}
rule SUSP_LNK_Embedded_ISO_FileHeader
{
	meta:
		author = "Greg Lesnewich"
		description = "look for LNK files that for some reason embed an ISO file based on LNK header and ISO header being valid"
		description = "ISO header rule borrowed from Lars https://github.com/100DaysofYARA/2024/blob/33cad5be966c9d959e8d38bd7669562f11a7b2a2/larsborn/Day_014.yara#L12"
		date = "2024-02-08"
		version = "1.0"
		DaysOfYara = "38/100"

	condition:
		uint32be(0x0) == 0x4c000000 and
		uint32be(0x8001) == 0x43443030 and
        	uint32be(0x8002) == 0x44303031  //CD001
}

rule SUSP_LNK_Embedded_ISO_NSRO_FileHeader
{
	meta:
		author = "Greg Lesnewich"
		description = "look for LNK files that for some reason embed an ISO file based on LNK header and ISO header being valid"
		description = "ISO header rule borrowed from Lars https://github.com/100DaysofYARA/2024/blob/33cad5be966c9d959e8d38bd7669562f11a7b2a2/larsborn/Day_014.yara#L12"
		date = "2024-02-08"
		version = "1.0"
		DaysOfYara = "38/100"

	condition:
		uint32be(0x0) == 0x4c000000 and
		(uint32be(0x8001) == 0x4E535230 or uint32be(0x9801) == 0x4E535230) // NSR0
}

rule SUSP_LNK_Embedded_ISO_In_Appended_Data
{
	meta:
		author = "Greg Lesnewich"
		description = "look for LNK files that for some reason embed an ISO file based on LNK header and ISO string being around the right place"
		description = "ISO header rule borrowed from Lars https://github.com/100DaysofYARA/2024/blob/33cad5be966c9d959e8d38bd7669562f11a7b2a2/larsborn/Day_014.yara#L12"
		date = "2024-02-01"
		version = "1.0"
		DaysOfYara = "38/100"
	strings:
		$iso = "CD001" ascii wide
	condition:
		uint32be(0x0) == 0x4c000000 and all of them and
		filesize > 0x8001 and
		$iso in (0x8000 .. 0x9002)
}

rule SUSP_LNK_Embedded_ISO_NSR0_In_Appended_Data
{
	meta:
		author = "Greg Lesnewich"
		description = "look for LNK files that for some reason embed an ISO file based on LNK header and ISO string being around the right place"
		description = "ISO header rule borrowed from Lars https://github.com/100DaysofYARA/2024/blob/33cad5be966c9d959e8d38bd7669562f11a7b2a2/larsborn/Day_014.yara#L12"
		date = "2024-02-08"
		version = "1.0"
		DaysOfYara = "38/100"
	strings:
		$NSR0 = "NSR0" ascii wide
	condition:
		uint32be(0x0) == 0x4c000000 and all of them and
		filesize > 0x8001 and
		$NSR0 in (0x8000 .. 0x9002)
}
rule SUSP_LNK_Embedded_WordDoc
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files with indications of the Word program or an embedded doc"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "2/100"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		filesize > 10KB and
		any of them
}
rule SUSP_LNK_Has_Appended_Data
{
    meta:
        author = "Greg Lesnewich, inspired by Jeremy Hedges"
        description = "track LNK files whose filesize is bigger than that recorded in the link header, suggesting appended data"
        date = "2024-02-01"
        version = "1.0"
        DaysOfYara = "33/100"

    condition:
        uint32be(0x0) == 0x4c000000 and
        uint32(0x34) != 0x0 and //offset of Link header that holds the filesize
        uint32(0x34) < filesize //compare integer in stored filesize field vs filesize
}

rule SUSP_LNK_Has_Wiped_FileSize
{
    meta:
        author = "Greg Lesnewich, inspired by Jeremy Hedges"
        description = "track LNK files that wipe the filesize information from the link header"
        date = "2024-02-01"
        version = "1.0"
        DaysOfYara = "33/100"

    condition:
        uint32be(0x0) == 0x4c000000 and
        uint32(0x34) == 0x0 //offset of Link header that holds the filesize
}
rule SUSP_LNK_Network_CloudServices_Discord
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
        $ = "cdn.discordapp.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "onedrive.live.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive_API
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "api.live.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDrive
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "drive.google.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDocs
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "docs.google.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_TransferSH
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "transfer.sh" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}


rule SUSP_LNK_Network_CloudServices_Discord_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
        $discord_base64 = "discord" base64 base64wide
        $discord_xor = "discord" xor(0x01-0xff) ascii wide
        $discord_flipflop = "idcsrod" nocase ascii wide
    	$discord_reverse = "drocsid" nocase ascii wide
    	$discord_hex_enc_str = "646973636f7264" nocase ascii wide
    	$discord_decimal = "100 105 115 99 111 114 100" nocase ascii wide
    	$discord_fallchill = "wrhxliw" nocase ascii wide
    	$discord_stackpush = "hordhdisc" nocase ascii wide
    	$discord_stackpushnull = "hord\x00hdisc"
    	$discord_stackpushdoublenull = "hord\x00\x00hdisc"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$onedrive_base64 = "onedrive" base64 base64wide
        $onedrive_xor = "onedrive" xor(0x01-0xff) ascii wide
        $onedrive_flipflop = "nodeirev" nocase ascii wide
    	$onedrive_reverse = "evirdeno" nocase ascii wide
    	$onedrive_hex_enc_str = "6f6e656472697665" nocase ascii wide
    	$onedrive_decimal = "111 110 101 100 114 105 118 101" nocase ascii wide
    	$onedrive_fallchill = "lmvwirev" nocase ascii wide
    	$onedrive_stackpush = "hrivehoned" nocase ascii wide
    	$onedrive_stackpushnull = "hrive\x00honed"
    	$onedrive_stackpushdoublenull = "hrive\x00\x00honed"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive_API_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$apilivecom_base64 = "api.live.com" base64 base64wide
        $apilivecom_xor = "api.live.com" xor(0x01-0xff) ascii wide
        $apilivecom_flipflop = "pa.iilevc.mo" nocase ascii wide
    	$apilivecom_reverse = "moc.evil.ipa" nocase ascii wide
    	$apilivecom_hex_enc_str = "6170692e6c6976652e636f6d" nocase ascii wide
    	$apilivecom_decimal = "97 112 105 46 108 105 118 101 46 99 111 109" nocase ascii wide
    	$apilivecom_fallchill = "akr.orev.xln" nocase ascii wide
    	$apilivecom_stackpush = "h.comhlivehapi." nocase ascii wide
    	$apilivecom_stackpushnull = "h.com\x00hlivehapi."
    	$apilivecom_stackpushdoublenull = "h.com\x00\x00hlivehapi."
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDrive_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$drivegooglecom_base64 = "drive.google.com" base64 base64wide
        $drivegooglecom_xor = "drive.google.com" xor(0x01-0xff) ascii wide
        $drivegooglecom_flipflop = "rdvi.eoggoelc.mo" nocase ascii wide
    	$drivegooglecom_reverse = "moc.elgoog.evird" nocase ascii wide
    	$drivegooglecom_hex_enc_str = "64726976652e676f6f676c652e636f6d" nocase ascii wide
    	$drivegooglecom_decimal = "100 114 105 118 101 46 103 111 111 103 108 101 46 99 111 109" nocase ascii wide
    	$drivegooglecom_fallchill = "wirev.tlltov.xln" nocase ascii wide
    	$drivegooglecom_stackpush = "h.comhoglehe.gohdriv" nocase ascii wide
    	$drivegooglecom_stackpushnull = "h.com\x00hoglehe.gohdriv"
    	$drivegooglecom_stackpushdoublenull = "h.com\x00\x00hoglehe.gohdriv"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDocs_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$docsgooglecom_base64 = "docs.google.com" base64 base64wide
        $docsgooglecom_xor = "docs.google.com" xor(0x01-0xff) ascii wide
        $docsgooglecom_flipflop = "odscg.oolg.eocm" nocase ascii wide
    	$docsgooglecom_reverse = "moc.elgoog.scod" nocase ascii wide
    	$docsgooglecom_hex_enc_str = "646f63732e676f6f676c652e636f6d" nocase ascii wide
    	$docsgooglecom_decimal = "100 111 99 115 46 103 111 111 103 108 101 46 99 111 109" nocase ascii wide
    	$docsgooglecom_fallchill = "wlxh.tlltov.xln" nocase ascii wide
    	$docsgooglecom_stackpush = "hcomhgle.h.goohdocs" nocase ascii wide
    	$docsgooglecom_stackpushnull = "hcom\x00hgle.h.goohdocs"
    	$docsgooglecom_stackpushdoublenull = "hcom\x00\x00hgle.h.goohdocs"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_TransferSH_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$transfer_base64 = "transfer.sh" base64 base64wide
        $transfer_xor = "transfer.sh" xor(0x01-0xff) ascii wide
        $transfersh_flipflop = "rtnafsres.h" nocase ascii wide
    	$transfersh_reverse = "hs.refsnart" nocase ascii wide
    	$transfersh_hex_enc_str = "7472616e736665722e7368" nocase ascii wide
    	$transfersh_decimal = "116 114 97 110 115 102 101 114 46 115 104" nocase ascii wide
    	$transfersh_fallchill = "giamhuvi.hs" nocase ascii wide
    	$transfersh_stackpush = "h.shhsferhtran" nocase ascii wide
    	$transfersh_stackpushnull = "h.s\x00hhsferhtran"
    	$transfersh_stackpushdoublenull = "h.s\x00\x00hhsferhtran"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}
rule SUSP_LNK_SmallScreenSize
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNKs that have a screen buffer size and WindowSize dimensions of 1x1"
		date = "2023-01-01"
		version = "1.0"
		DaysofYARA = "1/100"

	strings:
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}
		// struct ConsoleDataBlock sConsoleDataBlock
		// uint32 Size
		// uint32 Signature
		// enum FillAttributes
		// enum PopupFillAttributes
		// uint16 ScreenBufferSizeX
		// uint16 ScreenBufferSizeY
		// uint16 WindowSizeX
		// uint16 WindowSizeY
	condition:
		uint32be(0x0) == 0x4c000000 and all of them
}


rule MAL_Janicab_LNK
{
	meta:
		author = "Greg Lesnewich"
		description = "detect LNK files used in Janicab infection chain"
		date = "2023-01-01"
		version = "1.0"
		hash = "0c7e8427ee61672568983e51bf03e0bcf6f2e9c01d2524d82677b20264b23a3f"
		hash = "22ede766fba7551ad0b71ef568d0e5022378eadbdff55c4a02b42e63fcb3b17c"
		hash = "4920e6506ca557d486e6785cb5f7e4b0f4505709ffe8c30070909b040d3c3840"
		hash = "880607cc2da4c3213ea687dabd7707736a879cc5f2f1d4accf79821e4d24d870"
		hash = "f4610b65eba977b3d13eba5da0e38788a9e796a3e9775dd2b8e37b3085c2e1af"
		DaysofYARA = "1/100"

	strings:
		$j_pdf1 = "%PDF-1.5" ascii wide
		$j_cmd = "\\Windows\\System32\\cmd.exe" ascii wide
		$j_pdf_stream = "endstream" ascii wide
		$j_pdb_obj = "endobj" ascii wide
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}

	condition:
		uint32be(0x0) == 0x4C000000 and $dimensions and 2 of ($j_*)
}

rule SUSP_LoadLibraryA_mutation_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_b64 = "LoadLibraryA" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_xor = "LoadLibraryA" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_flipflop {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_flipflop = "oLdaiLrbraAy" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_flipflop_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_flipflop_b64 = "oLdaiLrbraAy" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_flipflop_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_flipflop_xor = "oLdaiLrbraAy" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_rot13 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_rot13 = "YbnqYvoenelN" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_rot13_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_rot13_b64 = "YbnqYvoenelN" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_rot13_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_rot13_xor = "YbnqYvoenelN" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_reverse {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_reverse = "AyrarbiLdaoL" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_reverse_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_reverse_b64 = "AyrarbiLdaoL" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_reverse_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_reverse_xor = "AyrarbiLdaoL" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str = "4c6f61644c69627261727941" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64 = "4c6f61644c69627261727941" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_xor = "4c6f61644c69627261727941" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_spaces {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_spaces = "4c 6f 61 64 4c 69 62 72 61 72 79 41" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_spaces_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_spaces_b64 = "4c 6f 61 64 4c 69 62 72 61 72 79 41" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_spaces_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_spaces_xor = "4c 6f 61 64 4c 69 62 72 61 72 79 41" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_commas = "4c,6f,61,64,4c,69,62,72,61,72,79,41" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_commas_b64 = "4c,6f,61,64,4c,69,62,72,61,72,79,41" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_commas_xor = "4c,6f,61,64,4c,69,62,72,61,72,79,41" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_double_hex_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_double_hex_enc_str = "346336663631363434633639363237323631373237393431" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_double_hex_enc_str_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_double_hex_enc_str_b64 = "346336663631363434633639363237323631373237393431" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_double_hex_enc_str_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_double_hex_enc_str_xor = "346336663631363434633639363237323631373237393431" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64_enc_str = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64_enc_str_b64 = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64_enc_str_xor = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_reversed = "14972716272696c44616f6c4" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_reversed_b64 = "14972716272696c44616f6c4" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_reversed_xor = "14972716272696c44616f6c4" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal = "76 111 97 100 76 105 98 114 97 114 121 65" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_b64 = "76 111 97 100 76 105 98 114 97 114 121 65" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_xor = "76 111 97 100 76 105 98 114 97 114 121 65" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_commas {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_commas = "76,111,97,100,76,105,98,114,97,114,121,65" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_commas_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_commas_b64 = "76,111,97,100,76,105,98,114,97,114,121,65" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_commas_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_commas_xor = "76,111,97,100,76,105,98,114,97,114,121,65" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_fallchill {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_fallchill = "LlawLryiaibA" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_fallchill_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_fallchill_b64 = "LlawLryiaibA" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_fallchill_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_fallchill_xor = "LlawLryiaibA" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpush {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpush = "haryAhLibrhLoad" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpush_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpush_b64 = "haryAhLibrhLoad" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpush_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpush_xor = "haryAhLibrhLoad" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpushnull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpushnull = "haryA\x00hLibrhLoad"
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpushdoublenull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpushdoublenull = "haryA\x00\x00hLibrhLoad"
	condition:
		all of them
}
rule SUSP_Macho_AES_CBC_Mode_XOR
{
		meta:
			author = "Greg Lesnewich"
			date = "2023-01-18"
			version = "1.0"
			description = "check Macho files for what might be an AES XOR routine used in its CBC mode "

		strings:
			$aes_cbc_xor_movs = {0fb6480141304c1d010fb6480241304c1d020fb6480341304c1d030fb6480441304c1d040fb6480541304c1d050fb6480641304c1d060fb6480741304c1d070fb6480841304c1d080fb6480941304c1d090fb6480a41304c1d0a0fb6480b41304c1d0b0fb6480c41304c1d0c0fb6480d41304c1d0d0fb6480e41304c1d0e0fb6400f4130441d0f}
		condition:
			(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
			1 of them
}
rule SUSP_Macho_Bin_Ref_bash {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like bash"
    strings:
        $ = "bin/bash" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_brew {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like brew"
    strings:
        $ = "bin/brew" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_chmH {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like chmH"
    strings:
        $ = "bin/chmH" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_chmod {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like chmod"
    strings:
        $ = "bin/chmod" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_chown {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like chown"
    strings:
        $ = "bin/chown" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_codesign {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like codesign"
    strings:
        $ = "bin/codesign" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_com {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like com"
    strings:
        $ = "bin/com" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_curl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like curl"
    strings:
        $ = "bin/curl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_defaults {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like defaults"
    strings:
        $ = "bin/defaults" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_diskutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like diskutil"
    strings:
        $ = "bin/diskutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_ditto {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like ditto"
    strings:
        $ = "bin/ditto" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_echo {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like echo"
    strings:
        $ = "bin/echo" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_find {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like find"
    strings:
        $ = "bin/find" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_hdiutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like hdiutil"
    strings:
        $ = "bin/hdiutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_iWorkServices {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like iWorkServices"
    strings:
        $ = "bin/iWorkServices" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_installer {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like installer"
    strings:
        $ = "bin/installer" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_jump {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like jump"
    strings:
        $ = "bin/jump" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_kextload {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like kextload"
    strings:
        $ = "bin/kextload" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_kextunload {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like kextunload"
    strings:
        $ = "bin/kextunload" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_kill {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like kill"
    strings:
        $ = "bin/kill" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_killall {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like killall"
    strings:
        $ = "bin/killall" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_launchctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like launchctl"
    strings:
        $ = "bin/launchctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_login {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like login"
    strings:
        $ = "bin/login" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_ls {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like ls"
    strings:
        $ = "bin/ls" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_mount {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like mount"
    strings:
        $ = "bin/mount" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_mv {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like mv"
    strings:
        $ = "bin/mv" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_my {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like my"
    strings:
        $ = "bin/my" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_networksetup {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like networksetup"
    strings:
        $ = "bin/networksetup" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_open {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like open"
    strings:
        $ = "bin/open" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_passwd {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like passwd"
    strings:
        $ = "bin/passwd" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_pkexec {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like pkexec"
    strings:
        $ = "bin/pkexec" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_pkgutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like pkgutil"
    strings:
        $ = "bin/pkgutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_python {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like python"
    strings:
        $ = "bin/python" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_rm {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like rm"
    strings:
        $ = "bin/rm" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_ruby {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like ruby"
    strings:
        $ = "bin/ruby" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_screencapture {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like screencapture"
    strings:
        $ = "bin/screencapture" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_sh {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like sh"
    strings:
        $ = "bin/sh" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_socat {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like socat"
    strings:
        $ = "bin/socat" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_spctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like spctl"
    strings:
        $ = "bin/spctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_sqlite3 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like sqlite3"
    strings:
        $ = "bin/sqlite3" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_sysctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like sysctl"
    strings:
        $ = "bin/sysctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_tar {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like tar"
    strings:
        $ = "bin/tar" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_tor {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like tor"
    strings:
        $ = "bin/tor" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_xauth {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like xauth"
    strings:
        $ = "bin/xauth" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_zip {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like zip"
    strings:
        $ = "bin/zip" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_ConventionEngine_Base64
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string "

    strings:
        $ = "base64" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        1 of them
}

rule SUSP_Macho_ConventionEngine_Hook {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Hook"
    strings:
        $ = "Hook" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Shellcode {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Shellcode"
    strings:
        $ = "Shellcode" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Rootkit {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Rootkit"
    strings:
        $ = "Rootkit" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Trojan {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Trojan"
    strings:
        $ = "Trojan" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Dropper {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Dropper"
    strings:
        $ = "Dropper" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Backdoor {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Backdoor"
    strings:
        $ = "Backdoor" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Spreader {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Spreader"
    strings:
        $ = "Spreader" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Loader {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Loader"
    strings:
        $ = "Loader" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}


rule SUSP_Macho_ConventionEngine_Inject {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Inject"
    strings:
        $ = "Inject" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}


rule SUSP_Macho_ConventionEngine_Reflect {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Reflect"
    strings:
        $ = "Reflect" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}
rule SUSP_Macho_Evasion_AntiDebug_sysctl
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-02"
		version = "1.0"
		description = "check Macho files for likely anti-debugging related strings like sysctl"
        	reference = "https://www.crowdstrike.com/blog/how-crowdstrike-analyzes-macos-malware-to-optimize-automated-detection-capabilities/"

	strings:
		$ = "sysctl" nocase ascii wide
	condition:
        	(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	all of them
}

rule SUSP_Macho_Evasion_AntiDebug_ptrace
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-02"
		version = "1.0"
		description = "check Macho files for likely anti-debugging related strings like ptrace"
        	reference = "https://www.crowdstrike.com/blog/how-crowdstrike-analyzes-macos-malware-to-optimize-automated-detection-capabilities/"

	strings:
		$ = "ptrace" nocase ascii wide
	condition:
        	(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	all of them
}

rule SUSP_Macho_Evasion_AntiDebug_sysctlbyname
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-02"
		version = "1.0"
		description = "check Macho files for likely anti-debugging related strings like sysctlbyname"
       		reference = "https://www.crowdstrike.com/blog/how-crowdstrike-analyzes-macos-malware-to-optimize-automated-detection-capabilities/"

	strings:
		$ = "sysctlbyname" nocase ascii wide
	condition:
        	(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	all of them
}

rule SUSP_Macho_Evasion_AntiDebug_sysctlnametomib
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-02"
		version = "1.0"
		description = "check Macho files for likely anti-debugging related strings like sysctlnametomib"
        	reference = "https://www.crowdstrike.com/blog/how-crowdstrike-analyzes-macos-malware-to-optimize-automated-detection-capabilities/"

	strings:
		$ = "sysctlnametomib" nocase ascii wide
	condition:
        	(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	all of them
}
rule SUSP_Macho_Execution_BinBash
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like bash shell"

    strings:
        $ = "bin/bash" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_Execution_Bin_sh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like sh shell"

    strings:
        $ = "bin/sh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_Execution_BinZsh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like zsh shell"

    strings:
        $ = "bin/zsh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}


rule SUSP_Macho_Execution_Bin_tcsh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like tcsh shell"

    strings:
        $ = "bin/tcsh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_Execution_CHMOD
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like chmod to mark files as executable"

    strings:
        $ = "chmod + x" ascii wide
        $ = "chmod +x" ascii wide
        $ = "chmod+x" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and any of them
}
rule SUSP_Macho_Keylog_Fields
{
	meta:
		author = "Greg Lesnewich"
		description = "specialized key strokes can be recorded with brackets around them in some MacOS samples - lets mine some!"
		date = "2023-02-03"
		version = "1.0"

	strings:
    	        $asterisk_keylog = "[asterisk]" ascii wide
    	        $caps_keylog = "[caps]" ascii wide
    	        $clear_keylog = "[clear]" ascii wide
    	        $decimal_keylog = "[decimal]" ascii wide
    	        $del_keylog = "[del]" ascii wide
    	        $divide_keylog = "[divide]" ascii wide
    	        $down_keylog = "[down]" ascii wide
    	        $end_keylog = "[end]" ascii wide
    	        $enter_keylog = "[enter]" ascii wide
    	        $equals_keylog = "[equals]" ascii wide
    	        $esc_keylog = "[esc]" ascii wide
    	        $f1_keylog = "[f1]" ascii wide
    	        $f10_keylog = "[f10]" ascii wide
    	        $f11_keylog = "[f11]" ascii wide
    	        $f12_keylog = "[f12]" ascii wide
    	        $f13_keylog = "[f13]" ascii wide
    	        $f14_keylog = "[f14]" ascii wide
    	        $f15_keylog = "[f15]" ascii wide
    	        $f16_keylog = "[f16]" ascii wide
    	        $f17_keylog = "[f17]" ascii wide
    	        $f18_keylog = "[f18]" ascii wide
    	        $f19_keylog = "[f19]" ascii wide
    	        $f2_keylog = "[f2]" ascii wide
    	        $f20_keylog = "[f20]" ascii wide
    	        $f3_keylog = "[f3]" ascii wide
    	        $f4_keylog = "[f4]" ascii wide
    	        $f5_keylog = "[f5]" ascii wide
    	        $f6_keylog = "[f6]" ascii wide
    	        $f7_keylog = "[f7]" ascii wide
    	        $f8_keylog = "[f8]" ascii wide
    	        $f9_keylog = "[f9]" ascii wide
    	        $fn_keylog = "[fn]" ascii wide
    	        $fwddel_keylog = "[fwddel]" ascii wide
    	        $help_keylog = "[help]" ascii wide
    	        $home_keylog = "[home]" ascii wide
    	        $hyphen_keylog = "[hyphen]" ascii wide
    	        $left_cmd_keylog = "[left-cmd]" ascii wide
    	        $left_ctrl_keylog = "[left-ctrl]" ascii wide
    	        $left_keylog = "[left]" ascii wide
    	        $left_option_keylog = "[left-option]" ascii wide
    	        $left_shift_keylog = "[left-shift]" ascii wide
    	        $mute_keylog = "[mute]" ascii wide
    	        $pgdown_keylog = "[pgdown]" ascii wide
    	        $pgup_keylog = "[pgup]" ascii wide
    	        $plus_keylog = "[plus]" ascii wide
    	        $return_keylog = "[return]" ascii wide
    	        $right_cmd_keylog = "[right-cmd]" ascii wide
    	        $right_ctrl_keylog = "[right-ctrl]" ascii wide
    	        $right_keylog = "[right]" ascii wide
    	        $right_option_keylog = "[right-option]" ascii wide
    	        $right_shift_keylog = "[right-shift]" ascii wide
    	        $tab_keylog = "[tab]" ascii wide
    	        $unknown_keylog = "[unknown]" ascii wide
    	        $up_keylog = "[up]" ascii wide
    	        $voldown_keylog = "[voldown]" ascii wide
    	        $volup_keylog = "[volup]" ascii wide
	condition:
        	(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	8 of them
}
rule SUSP_Macho_Base64_Encoded_Macho
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho magic bytes"

	strings:
		$CFFAEDFE = "\xCF\xFA\xED\xFE" base64 base64wide
		$CEFAEDFE = "\xCE\xFA\xED\xFE" base64 base64wide
		$text = "__TEXT" base64 base64wide
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and 2 of them
}

rule SUSP_Macho_XOR_Encoded_Macho
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho magic bytes"

	strings:
		$CFFAEDFE = "\xCF\xFA\xED\xFE" xor(0x01-0xff) ascii wide
		$CEFAEDFE = "\xCE\xFA\xED\xFE" xor(0x01-0xff) ascii wide
		$text = "__TEXT" xor(0x01-0xff) ascii wide
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and 2 of them
}

rule SUSP_UniversalBinary_Base64_Encoded_Macho
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho magic bytes"

	strings:
		$CFFAEDFE = "\xCF\xFA\xED\xFE" base64 base64wide
		$CEFAEDFE = "\xCE\xFA\xED\xFE" base64 base64wide
		$text = "__TEXT" base64 base64wide
	condition:
		uint32be(0x0) == 0xCAFEBABE and 2 of them
}

rule SUSP_UniversalBinary_XOR_Encoded_Macho
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho magic bytes"

	strings:
		$CFFAEDFE = "\xCF\xFA\xED\xFE" xor(0x01-0xff) ascii wide
		$CEFAEDFE = "\xCE\xFA\xED\xFE" xor(0x01-0xff) ascii wide
		$text = "__TEXT" xor(0x01-0xff) ascii wide
	condition:
		uint32be(0x0) == 0xCAFEBABE and 2 of them
}
rule SUSP_Macho_Second_Embedded_Macho
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho header structures"

	strings:
		$s = {(CFFAEDFE|CEFAEDFE) [30-38] 5F 5F 50 41 47 45 5A 45 52 4F [20-70] 5F 5F 54 45 58 54}

	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#s >= 2
}


rule SUSP_Macho_Second_MagicBytes
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho magic bytes"

	strings:
		$CFFAEDFE = {CFFAEDFE}
		$CEFAEDFE = {CEFAEDFE}
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		(#CFFAEDFE >= 2 or #CEFAEDFE >= 2)
}
rule SUSP_Macho_StackString_Library
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the path /Library being passed as a stack string"
    strings:
        $slash_library = {4? ?? 2f 4c 69 62 72 61 72 79 4? } // /Library passed to stack with the register wildcarded
	$library = {4? ?? 4c 69 62 72 61 72 79 4? } // Library passed to stack with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

rule SUSP_Macho_StackString_rmrf_Cmd
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the string rm -rf being passed as a stack string"
    strings:
        $rm_rf_stack = {4? ?? 72 6d 20 2d 72 66 4? } // rm rf string passed to stack with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

rule SUSP_Macho_StackString_UsersDir
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the path /Users/ being passed as a stack string"
    strings:
        $users_dir = {4? ?? 2f 55 73 65 72 73 2f 4? } // /Users/ passed to stack with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

rule SUSP_Macho_StackString_TAR
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the string tar zxvf or just tar  being passed as a stack string"
    strings:
        $tar_zxvf = {4? ?? 74 61 72 20 7a 78 76 66 4? } // tar zxvf passed to stack with the register wildcarded
	$tar_zxf = {4? ?? 74 61 72 20 7a 78 66 4? }
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}


rule SUSP_Macho_StackString_chmod
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the string chmod being passed as a stack string"
    strings:
        $chmod = {4? ?? 63 68 6d 6f 64 4? } // check for chmod being passed to the stack  with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}
rule SUSP_Macho_Usr_Ref_4bdy {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like 4bdy "
    strings:
        $ = "usr/4b/dy" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin "
    strings:
        $ = "usr/bin" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_inclu {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_inclu "
    strings:
        $ = "usr/bin/../inclu" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_include_c {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_include_c "
    strings:
        $ = "usr/bin/../include/c" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_codesign {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_codesign "
    strings:
        $ = "usr/bin/codesign" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_curl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_curl "
    strings:
        $ = "usr/bin/curl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_defaults {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_defaults "
    strings:
        $ = "usr/bin/defaults" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_diskutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_diskutil "
    strings:
        $ = "usr/bin/diskutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_ditto {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_ditto "
    strings:
        $ = "usr/bin/ditto" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_find {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_find "
    strings:
        $ = "usr/bin/find" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_hdiutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_hdiutil "
    strings:
        $ = "usr/bin/hdiutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_iWorkServices {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_iWorkServices "
    strings:
        $ = "usr/bin/iWorkServices" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_killall {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_killall "
    strings:
        $ = "usr/bin/killall" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_login {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_login "
    strings:
        $ = "usr/bin/login" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_open {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_open "
    strings:
        $ = "usr/bin/open" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_passwd {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_passwd "
    strings:
        $ = "usr/bin/passwd" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_pkexec {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_pkexec "
    strings:
        $ = "usr/bin/pkexec" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_python {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_python "
    strings:
        $ = "usr/bin/python" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_ruby {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_ruby "
    strings:
        $ = "usr/bin/ruby" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_sqlite3 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_sqlite3 "
    strings:
        $ = "usr/bin/sqlite3" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_tar {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_tar "
    strings:
        $ = "usr/bin/tar" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_bin_zip {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_zip "
    strings:
        $ = "usr/bin/zip" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_db_dyld {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like db_dyld "
    strings:
        $ = "usr/db/dyld" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_dict_words {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like dict_words "
    strings:
        $ = "usr/dict/words" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_ {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_ "
    strings:
        $ = "usr/include/" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_c {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_c "
    strings:
        $ = "usr/include/c" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_ctype {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_ctype "
    strings:
        $ = "usr/include/ctype" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_dispatch_once {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_dispatch_once "
    strings:
        $ = "usr/include/dispatch/once" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_dispatch_queue {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_dispatch_queue "
    strings:
        $ = "usr/include/dispatch/queue" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_libkern_i386 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_libkern_i386 "
    strings:
        $ = "usr/include/libkern/i386/" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_math {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_math "
    strings:
        $ = "usr/include/math" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_include_secure {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_secure "
    strings:
        $ = "usr/include/secure/" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_li {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like li "
    strings:
        $ = "usr/li" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib "
    strings:
        $ = "usr/lib" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Usr_Ref_lib_apple_SDKs {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_apple_SDKs "
    strings:
        $ = "usr/lib/apple/SDKs/" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_arc_libarclite {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_arc_libarclite "
    strings:
        $ = "usr/lib/arc/libarclite" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_dyld {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_dyld "
    strings:
        $ = "usr/lib/dyld" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_gcc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_gcc "
    strings:
        $ = "usr/lib/gcc/i686" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libDiagnosticMessagesClient {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libDiagnosticMessagesClient "
    strings:
        $ = "usr/lib/libDiagnosticMessagesClient." ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libSystem {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libSystem "
    strings:
        $ = "usr/lib/libSystem" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libc "
    strings:
        $ = "usr/lib/libc" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libcrypto {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libcrypto "
    strings:
        $ = "usr/lib/libcrypto" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libcurl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libcurl "
    strings:
        $ = "usr/lib/libcurl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libgcc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libgcc "
    strings:
        $ = "usr/lib/libgcc" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libiconv {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libiconv "
    strings:
        $ = "usr/lib/libiconv" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libicucore {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libicucore "
    strings:
        $ = "usr/lib/libicucore" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libobjc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libobjc "
    strings:
        $ = "usr/lib/libobjc" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libpcap {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libpcap "
    strings:
        $ = "usr/lib/libpcap" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libresolv {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libresolv "
    strings:
        $ = "usr/lib/libresolv" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libsqlite3 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libsqlite3 "
    strings:
        $ = "usr/lib/libsqlite3" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libstdc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libstdc "
    strings:
        $ = "usr/lib/libstdc" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libutil "
    strings:
        $ = "usr/lib/libutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_libz {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libz "
    strings:
        $ = "usr/lib/libz" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_lib_locale_TZ_GC {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_locale_TZ_GC "
    strings:
        $ = "usr/lib/locale/TZ/GC" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_libH {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like libH "
    strings:
        $ = "usr/libH" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_libexec_PlistBuddy {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like libexec_PlistBuddy "
    strings:
        $ = "usr/libexec/PlistBuddy" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_llvm {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like llvm "
    strings:
        $ = "usr/llvm" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local "
    strings:
        $ = "usr/local" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_McAfee {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_McAfee "
    strings:
        $ = "usr/local/McAfee" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin "
    strings:
        $ = "usr/local/bin" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin_brew {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_brew "
    strings:
        $ = "usr/local/bin/brew" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin_com_adobe_acc_installer {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_com_adobe_acc_installer "
    strings:
        $ = "usr/local/bin/com.adobe.acc.installer" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin_com_adobe_acc_localhost {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_com_adobe_acc_localhost "
    strings:
        $ = "usr/local/bin/com.adobe.acc.localhost" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin_com_adobe_acc_network {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_com_adobe_acc_network "
    strings:
        $ = "usr/local/bin/com.adobe.acc.network" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin_socat {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_socat "
    strings:
        $ = "usr/local/bin/socat" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_bin_tor {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_tor "
    strings:
        $ = "usr/local/bin/tor" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_go {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_go "
    strings:
        $ = "usr/local/go" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib "
    strings:
        $ = "usr/local/lib" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib_AdobePIM {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_AdobePIM "
    strings:
        $ = "usr/local/lib/AdobePIM" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib_ladspa {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_ladspa "
    strings:
        $ = "usr/local/lib/ladspa" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib_libvorbis {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_libvorbis "
    strings:
        $ = "usr/local/lib/libvorbis" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib_libvorbisenc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_libvorbisenc "
    strings:
        $ = "usr/local/lib/libvorbisenc" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib_libvorbisfile {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_libvorbisfile "
    strings:
        $ = "usr/local/lib/libvorbisfile" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_lib_sox {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_sox "
    strings:
        $ = "usr/local/lib/sox" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_sbin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_sbin "
    strings:
        $ = "usr/local/sbin" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_ssl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl "
    strings:
        $ = "usr/local/ssl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_ssl_cert_pem {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_cert_pem "
    strings:
        $ = "usr/local/ssl/cert.pem" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_ssl_certs {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_certs "
    strings:
        $ = "usr/local/ssl/certs" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_ssl_lib_engines {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_lib_engines "
    strings:
        $ = "usr/local/ssl/lib/engines" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_local_ssl_private {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_private "
    strings:
        $ = "usr/local/ssl/private" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin "
    strings:
        $ = "usr/sbin" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin_chown {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_chown "
    strings:
        $ = "usr/sbin/chown" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin_installer {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_installer "
    strings:
        $ = "usr/sbin/installer" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin_networksetup {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_networksetup "
    strings:
        $ = "usr/sbin/networksetup" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin_pkgutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_pkgutil "
    strings:
        $ = "usr/sbin/pkgutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin_screencapture {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_screencapture "
    strings:
        $ = "usr/sbin/screencapture" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_sbin_spctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_spctl "
    strings:
        $ = "usr/sbin/spctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_share_lib_zoneinfo {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_lib_zoneinfo "
    strings:
        $ = "usr/share/lib/zoneinfo/" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_share_lib_zoneinfo_bad {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_lib_zoneinfo_bad "
    strings:
        $ = "usr/share/lib/zoneinfo/bad" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_share_zoneinfo {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_zoneinfo "
    strings:
        $ = "usr/share/zoneinfo/" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_share_zoneinfo_EMULTIHOP {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_zoneinfo_EMULTIHOP "
    strings:
        $ = "usr/share/zoneinfo/EMULTIHOP" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_Macho_Usr_Ref_tmp {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like tmp "
    strings:
        $ = "usr/tmp" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}
rule SUSP_MacOS_CommandRef_networksetup
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $ = "networksetup" ascii wide
    condition:
        all of them
}


rule SUSP_MacOS_CommandRef_networksetup_b64
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $ = "networksetup" base64 base64wide
    condition:
        all of them
}

rule SUSP_MacOS_CommandRef_networksetup_xor
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $ = "networksetup" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_MacOS_CommandRef_networksetup_mutation
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $networksetup_flipflop = "enwtrosktepu" nocase ascii wide
        $networksetup_reverse = "puteskrowten" nocase ascii wide
        $networksetup_hex_enc_str = "6e6574776f726b7365747570" nocase ascii wide
        $networksetup_decimal = "110 101 116 119 111 114 107 115 101 116 117 112" nocase ascii wide
        $networksetup_fallchill = "mvgdliphvgfk" nocase ascii wide
        $networksetup_stackpush = "hetuphorkshnetw" nocase ascii wide
        $networksetup_stackpushnull = "hetup\x00horkshnetw" ascii wide
        $networksetup_stackpushdoublenull = "hetup\x00\x00horkshnetw" ascii wide
    condition:
        all of them
}
rule SUSP_MacOS_Injection_API_NSLinkModule
{
    meta:
        author = "Greg Lesnewich"
        description = "basic string check for older dyld API's used for payload injection"
        date = "2023-01-15"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
        reference = "https://twitter.com/patrickwardle/status/1547967373264560131"
        version = "1.0"
        DaysofYARA = "15/100"

    strings:
        $ = "NSLinkModule" nocase ascii wide
    condition:
        all of them
}


rule SUSP_MacOS_Injection_API_NSCreateObjectFileImageFromMemory
{
    meta:
        author = "Greg Lesnewich"
        description = "basic string check for older dyld API's used for payload injection"
        date = "2023-01-15"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
        reference = "https://twitter.com/patrickwardle/status/1547967373264560131"
        version = "1.0"
        DaysofYARA = "15/100"

    strings:
        $ = "NSCreateObjectFileImageFromMemory" nocase ascii wide
    condition:
        all of them
}
import "pe"

rule SUSP_MinimalImports_LoadLibrary_and_GetModuleFileName
{
	meta:
		author = "Greg Lesnewich"
		description = "look for PE's that import less than 10 functions, 2 of which are variants of LoadLibrary and GetModuleFileName, likely to resolve additional APIs"
		date = "2024-01-26"
		version = "1.0"
		DaysOfYara = "26/100"

	condition:
		pe.number_of_imported_functions < 10 and
		pe.imports(/kernel32.dll/i, /LoadLibrary(A|ExA|ExW|W)/i) and
		pe.imports(/kernel32.dll/i, /GetModuleFileName(A|ExA|ExW|W)/i)
}

rule SUSP_MinimalImports_LoadLibrary_and_GetProcAddress
{
	meta:
		author = "Greg Lesnewich"
		description = "look for PE's that import less than 10 functions, 2 of which are variants of LoadLibrary and GetProcAddress, likely to resolve additional APIs"
		date = "2024-01-26"
		version = "1.0"
		DaysOfYara = "26/100"

	condition:
		pe.number_of_imported_functions < 10 and
		pe.imports(/kernel32.dll/i, /LoadLibrary(A|ExA|ExW|W)/i) and
		pe.imports("kernel32.dll", "GetProcAddress")
}
rule SUSP_ntdlldll_mutation_flipflop {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_flipflop = "tnld.lldl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_reverse {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_reverse = "lld.lldtn" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_hex_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_hex_enc_str = "6e74646c6c2e646c6c" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_decimal {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_decimal = "110 116 100 108 108 46 100 108 108" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_fallchill {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_fallchill = "mgwoo.woo" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_stackpush {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_stackpush = "hlhl.dlhntdl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_stackpushnull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_stackpushnull = "hl\x00hl.dlhntdl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_stackpushdoublenull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_stackpushdoublenull = "hl\x00\x00hl.dlhntdl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_hex_movebp {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_hex_movebp = {c645??6ec645??74c645??64c645??6cc645??6cc645??2ec645??64c645??6cc645??6c}
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_rot13 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_rot13 = "agqyy.qyy" ascii wide nocase
	condition:
		all of them
}



rule ntdll_flipflop { strings: $ntdll_flipflop = "tnldl" nocase ascii wide condition: all of them }
rule ntdll_reverse { strings: $ntdll_reverse = "lldtn" nocase ascii wide condition: all of them }
rule ntdll_hex_enc_str { strings: $ntdll_hex_enc_str = "6e74646c6c" nocase ascii wide condition: all of them }
rule ntdll_decimal { strings: $ntdll_decimal = "110 116 100 108 108" nocase ascii wide condition: all of them }
rule ntdll_fallchill { strings: $ntdll_fallchill = "mgwoo" nocase ascii wide condition: all of them }
rule ntdll_stackpush { strings: $ntdll_stackpush = "hlhntdl" nocase ascii wide condition: all of them }
rule ntdll_stackpushnull { strings: $ntdll_stackpushnull = "hl\x00hntdl" nocase ascii wide condition: all of them }
rule ntdll_stackpushdoublenull { strings: $ntdll_stackpushdoublenull = "hl\x00\x00hntdl" nocase ascii wide condition: all of them }
rule ntdll_hex_movebp { strings: $ntdll_hex_movebp = {c645??6ec645??74c645??64c645??6cc645??6c} condition: all of them }
rule ntdll_rot13 { strings: $ntdll_rot13 = "agqyy" nocase ascii wide condition: all of them }



rule zSUSP_NTDLL_Stack_String_Padding
{
	meta:
		author = "Greg Lesnewich"
		description = "detect ntdll.dll being moved to the stack with empty padding being used to clear the register prior to use"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "23/100"

	strings:
		$0x1d5c1369a = { 20202020 ?? 6e74646c [10 - 20] 20202020 ?? 6c2e646c }
		    // 1d5c1369a  0d20202020         or      eax, 0x20202020
		    // 1d5c1369f  3d6e74646c         cmp     eax, 'ntdl'
		    // 1d5c136a4  751b               jne     0x1d5c136c1
		    // 1d5c136a6  488b4598           mov     rax, qword [rbp-0x68 {var_80_1}]
		    // 1d5c136aa  4883c004           add     rax, 0x4
		    // 1d5c136ae  8b00               mov     eax, dword [rax]
		    // 1d5c136b0  0d20202020         or      eax, 0x20202020
		    // 1d5c136b5  3d6c2e646c         cmp     eax, 'l.dl'
	condition:
		all of them
}

rule SUSP_Obfuscated_Mozilla_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_b64 = "Mozilla" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_xor = "Mozilla" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_flipflop {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_flipflop = "oMizlla" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_flipflop_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_flipflop_b64 = "oMizlla" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_flipflop_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_flipflop_xor = "oMizlla" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_rot13 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_rot13 = "Zbmvyyn" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_rot13_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_rot13_b64 = "Zbmvyyn" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_rot13_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_rot13_xor = "Zbmvyyn" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_reverse {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_reverse = "allizoM" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_reverse_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_reverse_b64 = "allizoM" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_reverse_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_reverse_xor = "allizoM" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str = "4d6f7a696c6c61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64 = "4d6f7a696c6c61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_xor = "4d6f7a696c6c61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_spaces = "4d 6f 7a 69 6c 6c 61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_spaces_b64 = "4d 6f 7a 69 6c 6c 61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_spaces_xor = "4d 6f 7a 69 6c 6c 61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_commas {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_commas = "4d,6f,7a,69,6c,6c,61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_commas_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_commas_b64 = "4d,6f,7a,69,6c,6c,61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_commas_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_commas_xor = "4d,6f,7a,69,6c,6c,61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_double_hex_enc_str {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_double_hex_enc_str = "3464366637613639366336633631" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_double_hex_enc_str_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_double_hex_enc_str_b64 = "3464366637613639366336633631" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_double_hex_enc_str_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_double_hex_enc_str_xor = "3464366637613639366336633631" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64_enc_str = "NGQ2ZjdhNjk2YzZjNjE=" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64_enc_str_b64 = "NGQ2ZjdhNjk2YzZjNjE=" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64_enc_str_xor = "NGQ2ZjdhNjk2YzZjNjE=" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_reversed = "16c6c696a7f6d4" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_reversed_b64 = "16c6c696a7f6d4" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_reversed_xor = "16c6c696a7f6d4" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal = "77 111 122 105 108 108 97" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_b64 = "77 111 122 105 108 108 97" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_xor = "77 111 122 105 108 108 97" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_commas {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_commas = "77,111,122,105,108,108,97" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_commas_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_commas_b64 = "77,111,122,105,108,108,97" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_commas_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_commas_xor = "77,111,122,105,108,108,97" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_fallchill {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_fallchill = "Mlzrooa" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_fallchill_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_fallchill_b64 = "Mlzrooa" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_fallchill_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_fallchill_xor = "Mlzrooa" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpush {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpush = "hllahMozi" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpush_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpush_b64 = "hllahMozi" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpush_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpush_xor = "hllahMozi" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpushnull {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpushnull = "hlla\x00hMozi" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpushdoublenull {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpushdoublenull = "hlla\x00\x00hMozi" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_url_encoded {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_url_encoded = "4d%6f%7a%69%6c%6c%61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_url_encoded_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_url_encoded_b64 = "4d%6f%7a%69%6c%6c%61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_url_encoded_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_url_encoded_xor = "4d%6f%7a%69%6c%6c%61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}
rule SUSP_Obfuscated_Powershell_Casing_Anomaly {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via casing anomalies"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $case1 = "Powershell" nocase ascii wide
    $case2 = "powershell" nocase ascii wide
    $legit1 = "powershell" ascii wide
    $legit2 = "Powershell" ascii wide
  condition:
    none of ($legit*) and any of ($case*)
}


rule SUSP_Obfuscated_Powershell_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $ = "powershell" base64 base64wide
    $ = "Powershell" base64 base64wide
    $ = "PowerShell" base64 base64wide
    $ = "POWERSHELL" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $ = "powershell" xor(0x01-0xff) ascii wide
    $ = "Powershell" xor(0x01-0xff) ascii wide
    $ = "PowerShell" xor(0x01-0xff) ascii wide
    $ = "POWERSHELL" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_flipflop {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_flipflop = "opewsrehll" nocase ascii wide
    $PowerShell_flipflop = "oPewSrehll" nocase ascii wide
    $Powershell_flipflop = "oPewsrehll" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_flipflop_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_flipflop_b64 = "opewsrehll" base64 base64wide
    $PowerShell_flipflop_b64 = "oPewSrehll" base64 base64wide
    $Powershell_flipflop_b64 = "oPewsrehll" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_flipflop_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_flipflop_xor = "opewsrehll" xor(0x01-0xff) ascii wide
    $PowerShell_flipflop_xor = "oPewSrehll" xor(0x01-0xff) ascii wide
    $Powershell_flipflop_xor = "oPewsrehll" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_rot13 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_rot13 = "cbjrefuryy" nocase ascii wide
    $PowerShell_rot13 = "CbjreFuryy" nocase ascii wide
    $Powershell_rot13 = "Cbjrefuryy" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_rot13_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_rot13_b64 = "cbjrefuryy" base64 base64wide
    $PowerShell_rot13_b64 = "CbjreFuryy" base64 base64wide
    $Powershell_rot13_b64 = "Cbjrefuryy" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_rot13_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_rot13_xor = "cbjrefuryy" xor(0x01-0xff) ascii wide
    $PowerShell_rot13_xor = "CbjreFuryy" xor(0x01-0xff) ascii wide
    $Powershell_rot13_xor = "Cbjrefuryy" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_reverse {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_reverse = "llehsrewop" nocase ascii wide
    $PowerShell_reverse = "llehSrewoP" nocase ascii wide
    $Powershell_reverse = "llehsrewoP" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_reverse_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_reverse_b64 = "llehsrewop" base64 base64wide
    $PowerShell_reverse_b64 = "llehSrewoP" base64 base64wide
    $Powershell_reverse_b64 = "llehsrewoP" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_reverse_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_reverse_xor = "llehsrewop" xor(0x01-0xff) ascii wide
    $PowerShell_reverse_xor = "llehSrewoP" xor(0x01-0xff) ascii wide
    $Powershell_reverse_xor = "llehsrewoP" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str = "706f7765727368656c6c" nocase ascii wide
    $PowerShell_hex_enc_str = "506f7765725368656c6c" nocase ascii wide
    $Powershell_hex_enc_str = "506f7765727368656c6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64 = "706f7765727368656c6c" base64 base64wide
    $PowerShell_hex_enc_str_b64 = "506f7765725368656c6c" base64 base64wide
    $Powershell_hex_enc_str_b64 = "506f7765727368656c6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_xor = "706f7765727368656c6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_xor = "506f7765725368656c6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_xor = "506f7765727368656c6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_spaces = "70 6f 77 65 72 73 68 65 6c 6c" nocase ascii wide
    $PowerShell_hex_enc_str_spaces = "50 6f 77 65 72 53 68 65 6c 6c" nocase ascii wide
    $Powershell_hex_enc_str_spaces = "50 6f 77 65 72 73 68 65 6c 6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_spaces_b64 = "70 6f 77 65 72 73 68 65 6c 6c" base64 base64wide
    $PowerShell_hex_enc_str_spaces_b64 = "50 6f 77 65 72 53 68 65 6c 6c" base64 base64wide
    $Powershell_hex_enc_str_spaces_b64 = "50 6f 77 65 72 73 68 65 6c 6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_spaces_xor = "70 6f 77 65 72 73 68 65 6c 6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_spaces_xor = "50 6f 77 65 72 53 68 65 6c 6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_spaces_xor = "50 6f 77 65 72 73 68 65 6c 6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_commas {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_commas = "70,6f,77,65,72,73,68,65,6c,6c" nocase ascii wide
    $PowerShell_hex_enc_str_commas = "50,6f,77,65,72,53,68,65,6c,6c" nocase ascii wide
    $Powershell_hex_enc_str_commas = "50,6f,77,65,72,73,68,65,6c,6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_commas_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_commas_b64 = "70,6f,77,65,72,73,68,65,6c,6c" base64 base64wide
    $PowerShell_hex_enc_str_commas_b64 = "50,6f,77,65,72,53,68,65,6c,6c" base64 base64wide
    $Powershell_hex_enc_str_commas_b64 = "50,6f,77,65,72,73,68,65,6c,6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_commas_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_commas_xor = "70,6f,77,65,72,73,68,65,6c,6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_commas_xor = "50,6f,77,65,72,53,68,65,6c,6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_commas_xor = "50,6f,77,65,72,73,68,65,6c,6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_double_hex_enc_str {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_double_hex_enc_str = "3730366637373635373237333638363536633663" nocase ascii wide
    $PowerShell_double_hex_enc_str = "3530366637373635373235333638363536633663" nocase ascii wide
    $Powershell_double_hex_enc_str = "3530366637373635373237333638363536633663" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_double_hex_enc_str_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_double_hex_enc_str_b64 = "3730366637373635373237333638363536633663" base64 base64wide
    $PowerShell_double_hex_enc_str_b64 = "3530366637373635373235333638363536633663" base64 base64wide
    $Powershell_double_hex_enc_str_b64 = "3530366637373635373237333638363536633663" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_double_hex_enc_str_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_double_hex_enc_str_xor = "3730366637373635373237333638363536633663" xor(0x01-0xff) ascii wide
    $PowerShell_double_hex_enc_str_xor = "3530366637373635373235333638363536633663" xor(0x01-0xff) ascii wide
    $Powershell_double_hex_enc_str_xor = "3530366637373635373237333638363536633663" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64_enc_str = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" nocase ascii wide
    $PowerShell_hex_enc_str_b64_enc_str = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" nocase ascii wide
    $Powershell_hex_enc_str_b64_enc_str = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64_enc_str_b64 = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" base64 base64wide
    $PowerShell_hex_enc_str_b64_enc_str_b64 = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" base64 base64wide
    $Powershell_hex_enc_str_b64_enc_str_b64 = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64_enc_str_xor = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_b64_enc_str_xor = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_b64_enc_str_xor = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_reversed = "c6c6568637275677f607" nocase ascii wide
    $PowerShell_hex_enc_str_reversed = "c6c6568635275677f605" nocase ascii wide
    $Powershell_hex_enc_str_reversed = "c6c6568637275677f605" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_reversed_b64 = "c6c6568637275677f607" base64 base64wide
    $PowerShell_hex_enc_str_reversed_b64 = "c6c6568635275677f605" base64 base64wide
    $Powershell_hex_enc_str_reversed_b64 = "c6c6568637275677f605" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_reversed_xor = "c6c6568637275677f607" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_reversed_xor = "c6c6568635275677f605" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_reversed_xor = "c6c6568637275677f605" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal = "112 111 119 101 114 115 104 101 108 108" nocase ascii wide
    $PowerShell_decimal = "80 111 119 101 114 83 104 101 108 108" nocase ascii wide
    $Powershell_decimal = "80 111 119 101 114 115 104 101 108 108" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_b64 = "112 111 119 101 114 115 104 101 108 108" base64 base64wide
    $PowerShell_decimal_b64 = "80 111 119 101 114 83 104 101 108 108" base64 base64wide
    $Powershell_decimal_b64 = "80 111 119 101 114 115 104 101 108 108" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_xor = "112 111 119 101 114 115 104 101 108 108" xor(0x01-0xff) ascii wide
    $PowerShell_decimal_xor = "80 111 119 101 114 83 104 101 108 108" xor(0x01-0xff) ascii wide
    $Powershell_decimal_xor = "80 111 119 101 114 115 104 101 108 108" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_commas {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_commas"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_commas = "112,111,119,101,114,115,104,101,108,108" nocase ascii wide
    $PowerShell_decimal_commas = "80,111,119,101,114,83,104,101,108,108" nocase ascii wide
    $Powershell_decimal_commas = "80,111,119,101,114,115,104,101,108,108" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_commas_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_commas_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_commas_b64 = "112,111,119,101,114,115,104,101,108,108" base64 base64wide
    $PowerShell_decimal_commas_b64 = "80,111,119,101,114,83,104,101,108,108" base64 base64wide
    $Powershell_decimal_commas_b64 = "80,111,119,101,114,115,104,101,108,108" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_commas_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_commas_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_commas_xor = "112,111,119,101,114,115,104,101,108,108" xor(0x01-0xff) ascii wide
    $PowerShell_decimal_commas_xor = "80,111,119,101,114,83,104,101,108,108" xor(0x01-0xff) ascii wide
    $Powershell_decimal_commas_xor = "80,111,119,101,114,115,104,101,108,108" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_fallchill {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_fallchill = "kldvihsvoo" nocase ascii wide
    $PowerShell_fallchill = "PldviSsvoo" nocase ascii wide
    $Powershell_fallchill = "Pldvihsvoo" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_fallchill_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_fallchill_b64 = "kldvihsvoo" base64 base64wide
    $PowerShell_fallchill_b64 = "PldviSsvoo" base64 base64wide
    $Powershell_fallchill_b64 = "Pldvihsvoo" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_fallchill_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_fallchill_xor = "kldvihsvoo" xor(0x01-0xff) ascii wide
    $PowerShell_fallchill_xor = "PldviSsvoo" xor(0x01-0xff) ascii wide
    $Powershell_fallchill_xor = "Pldvihsvoo" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpush {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpush = "hllhrshehpowe" nocase ascii wide
    $PowerShell_stackpush = "hllhrShehPowe" nocase ascii wide
    $Powershell_stackpush = "hllhrshehPowe" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpush_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpush_b64 = "hllhrshehpowe" base64 base64wide
    $PowerShell_stackpush_b64 = "hllhrShehPowe" base64 base64wide
    $Powershell_stackpush_b64 = "hllhrshehPowe" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpush_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpush_xor = "hllhrshehpowe" xor(0x01-0xff) ascii wide
    $PowerShell_stackpush_xor = "hllhrShehPowe" xor(0x01-0xff) ascii wide
    $Powershell_stackpush_xor = "hllhrshehPowe" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpushnull {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpushnull"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpushnull = "hll\x00hrshehpowe" nocase ascii wide
    $PowerShell_stackpushnull = "hll\x00hrShehPowe" nocase ascii wide
    $Powershell_stackpushnull = "hll\x00hrshehPowe" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpushdoublenull {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpushdoublenull"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpushdoublenull = "hll\x00\x00hrshehpowe" nocase ascii wide
    $PowerShell_stackpushdoublenull = "hll\x00\x00hrShehPowe" nocase ascii wide
    $Powershell_stackpushdoublenull = "hll\x00\x00hrshehPowe" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_url_encoded {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_url_encoded = "70%6f%77%65%72%73%68%65%6c%6c" nocase ascii wide
    $PowerShell_url_encoded = "50%6f%77%65%72%53%68%65%6c%6c" nocase ascii wide
    $Powershell_url_encoded = "50%6f%77%65%72%73%68%65%6c%6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_url_encoded_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_url_encoded_b64 = "70%6f%77%65%72%73%68%65%6c%6c" base64 base64wide
    $PowerShell_url_encoded_b64 = "50%6f%77%65%72%53%68%65%6c%6c" base64 base64wide
    $Powershell_url_encoded_b64 = "50%6f%77%65%72%73%68%65%6c%6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_url_encoded_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_url_encoded_xor = "70%6f%77%65%72%73%68%65%6c%6c" xor(0x01-0xff) ascii wide
    $PowerShell_url_encoded_xor = "50%6f%77%65%72%53%68%65%6c%6c" xor(0x01-0xff) ascii wide
    $Powershell_url_encoded_xor = "50%6f%77%65%72%73%68%65%6c%6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}
import "pe"

rule SUSP_PE_HashLike_DLL_Name_MD5
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        pe.dll_name matches /[a-z0-9A-Z]{32}.dll/
}

rule SUSP_PE_HashLike_DLL_Name_SHA256
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        pe.dll_name matches /[a-z0-9A-Z]{64}.dll/
}

rule SUSP_PE_HashLike_DLL_Name_SHA1
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        pe.dll_name matches /[a-z0-9A-Z]{40}.dll/
}

rule SUSP_PE_HashLike_Resource_Name_MD5
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        for any rsrc in pe.resources:
        (
            rsrc.name_string matches /([a-z0-9A-Z]{1}\x00){32}/ or
            rsrc.type_string matches /([a-z0-9A-Z]{1}\x00){32}/
        )
}

rule SUSP_PE_HashLike_Resource_Name_SHA1
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        for any rsrc in pe.resources:
        (
            rsrc.name_string matches /([a-z0-9A-Z]{1}\x00){40}/ or
            rsrc.type_string matches /([a-z0-9A-Z]{1}\x00){40}/
        )
}

rule SUSP_PE_HashLike_Resource_Name_SHA256
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        for any rsrc in pe.resources:
        (
            rsrc.name_string matches /([a-z0-9A-Z]{1}\x00){64}/ or
            rsrc.type_string matches /([a-z0-9A-Z]{1}\x00){64}/
        )
}
rule SUSP_PE_References_Lua
{
	meta:
		author = "Greg Lesnewich"
		date = "2024-01-08"
		version = "1.0"
		DaysOfYara = "9/100"
		description = "look for executable files that reference Lua error names, Lua libraries, or Lua debug flags"
		reference = "https://web.archive.org/web/20150311013500/http://www.cyphort.com/evilbunny-malware-instrumented-lua/"
		reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07190154/The-ProjectSauron-APT_research_KL.pdf"
		reference = "https://securelist.com/the-flame-questions-and-answers/34344/"
		hash = "d737644d612e5051f66fb97a34ec592b3508be06e33f743a2fdb31cdf6bd2718" // REMSEC
		hash = "295b089792d00870db938f2107772e0b58b23e5e8c6c4465c23affe87e2e67ac" // FLAME
		hash = "be14d781b85125a6074724964622ab05f89f41e6bacbda398bc7709d1d98a2ef" // Bunny
		hash = "c6a182f410b4cda0665cd792f00177c56338018fbc31bb34e41b72f8195c20cc" // Bunny

	strings:
		$ = "Lua function expected" ascii wide
		$ = "lua_debug" ascii wide
		$ = "lua.libs" nocase ascii wide
	condition:
		uint16be(0) == 0x4d5a and
		filesize <10MB and
		1 of them
}
import "pe"

rule SUSP_PE_RSRCs_Name_Strings_64_and_32_Refs
{
	meta:
		description = "check for PEs that contain both 64 and 32/86 in resource names, potentially indicating second-stage payloads based on bitness"
		author = "Greg Lesnewich"
		date = "2024-01-15"
		version = "1.0"
		DaysofYARA = "15/100"
	condition:
		for any rsrc in pe.resources:
		(
			rsrc.name_string contains "3\x002\x00" or
			rsrc.name_string contains "8\x006\x00"
		)

		and for any rsrc in pe.resources:
		(
			rsrc.name_string contains "6\x004\x00"
			)

}


rule SUSP_PE_RSRCs_Type_Strings_64_and_32_Refs
{
	meta:
		description = "check for PEs that contain both 64 and 32/86 in resource types, potentially indicating second-stage payloads based on bitness"
		author = "Greg Lesnewich"
		date = "2024-01-15"
		version = "1.0"
		DaysofYARA = "15/100"
	condition:
		for any rsrc in pe.resources:
		(
			rsrc.type_string contains "3\x002\x00" or
			rsrc.type_string contains "8\x006\x00"
		)

		and for any rsrc in pe.resources:
		(
			rsrc.type_string contains "6\x004\x00"
			)

}
import "pe"
rule SUSP_PE_Unusual_Imported_Library_Names

{
	meta:
		description = "look for PE's whose imported libraries don't end in DLL, and aren't common EXE names"
		author = "Greg Lesnewich"
		date = "2024-01-14"
		version = "1.0"
		DaysOfYARA = "14/100"

	condition:
		for any imp in pe.import_details:
		(
			not imp.library_name iendswith ".dll" and
			not imp.library_name iequals "WINSPOOL.DRV" and
			not imp.library_name iequals "ntoskrnl.exe"
		)
}
rule SUSP_References_Likely_Traffic_Listening_Network_Interface
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to Network-Interface that might get used for traffic sniffing"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "Network-Interface" nocase ascii wide
        $  = "Network Interface" nocase ascii wide
    condition:
        1 of them
}


rule SUSP_References_Likely_Traffic_Capture_eth0
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to eth0 that might get used for traffic capture"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "eth0" nocase ascii wide
    condition:
        1 of them
}


rule SUSP_References_Likely_Traffic_Capture_802_11
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to 802.11 that might get used for localized traffic capture"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "802.11" ascii wide
    condition:
        1 of them
}
import "pe"

rule TTP_RegOpenKeyExA_HKEY_LOCAL_MACHINE_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_LOCAL_MACHINE keys (const 0x80000002) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 02 00 00 80          push    0x80000002 {var_15c_1}  {0x80000002} //HKEY_LOCAL_MACHINE
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6802000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}



rule TTP_RegOpenKeyExA_HKEY_LOCAL_MACHINE_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_LOCAL_MACHINE keys (const 0x80000002) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {02 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_CLASSES_ROOT_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CLASSES_ROOT keys (const 0x80000000) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 00 00 00 80          push    0x80000000 {var_15c_1}  {0x80000000} //HKEY_CLASSES_ROOT
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6800000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_CLASSES_ROOT_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CLASSES_ROOT keys (const 0x80000000) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        $reg_open_key_call = {00 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_CURRENT_USER_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_USER keys (const 0x80000001) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 01 00 00 80          push    0x80000001 {var_15c_1}  {0x80000001} //HKEY_CURRENT_USER
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6801000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_CURRENT_USER_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_USER keys (const 0x80000001) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {01 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_USERS_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_USERS keys (const 0x80000003) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 01 00 00 80          push    0x80000003 {var_15c_1}  {0x80000003} //HKEY_USERS
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6803000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_USERS_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_USERS keys (const 0x80000003) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {03 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_DATA_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_DATA keys (const 0x80000004) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 01 00 00 80          push    0x80000004 {var_15c_1}  {0x80000004} //HKEY_PERFORMANCE_DATA
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6804000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_DATA_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_DATA keys (const 0x80000004) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {04 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}
rule TTP_RegOpenKeyExA_HKEY_CURRENT_CONFIG_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_CONFIG keys (const 0x80000005) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 05 00 00 80          push    0x80000005 {var_15c_1}  {0x80000005} //HKEY_CURRENT_CONFIG
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6805000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_CURRENT_CONFIG_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_CONFIG keys (const 0x80000005) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {05 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}



rule TTP_RegOpenKeyExA_HKEY_DYN_DATA_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_DYN_DATA keys (const 0x80000006) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 06 00 00 80          push    0x80000006 {var_15c_1}  {0x80000006} //HKEY_DYN_DATA
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6806000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_DYN_DATA_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_DYN_DATA keys (const 0x80000006) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {06 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_TEXT_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_TEXT keys (const 0x80000050) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 50 00 00 80          push    0x80000050 {var_15c_1}  {0x80000050} //HKEY_PERFORMANCE_TEXT
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6850000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_TEXT_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_TEXT keys (const 0x80000050) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {50 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_NLSTEXT_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_NLSTEXT keys (const 0x80000060) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 60 00 00 80          push    0x80000060 {var_15c_1}  {0x80000060} //HKEY_PERFORMANCE_NLSTEXT
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6860000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_NLSTEXT_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_NLSTEXT keys (const 0x80000060) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {60 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}
