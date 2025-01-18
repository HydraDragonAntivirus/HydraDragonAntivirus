// Animal Farm yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule ramFS
{
    meta:
        Author      = "Joan Calvet"
        Date        = "2015/07/14"
        Description = "RamFS -- custom file system used by Animal Farm malware"
        Reference   = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $mz = { 4d 5a }

        // Debug strings in RamFS
        $s01 = "Check: Error in File_List"
        $s02 = "Check: Error in FreeFileHeader_List"
        $s03 = "CD-->[%s]"
        $s04 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]"
        // RamFS parameters stored in the configuration
        $s05 = "tr4qa589" fullword
        $s06 = "xT0rvwz" fullword

        // RamFS commands
        $c01 = "INSTALL" fullword
        $c02 = "EXTRACT" fullword
        $c03 = "DELETE" fullword
        $c04 = "EXEC" fullword
        $c05 = "INJECT" fullword
        $c06 = "SLEEP" fullword
        $c07 = "KILL" fullword
        $c08 = "AUTODEL" fullword
        $c09 = "CD" fullword
        $c10 = "MD" fullword        

    condition:
        ( $mz at 0 ) and
            ((1 of ($s*)) or (all of ($c*)))
}

rule dino
{
    meta:
        Author      = "Joan Calvet"
        Date        = "2015/07/14"
        Description = "Dino backdoor"
        Reference   = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $ = "PsmIsANiceM0du1eWith0SugarInsideA"
        $ = "destroyPSM"
        $ = "FM_PENDING_DOWN_%X"
        $ = "%s was canceled after %d try (reached MaxTry parameter)"
        $ = "you forgot value name"
        $ = "wakeup successfully scheduled in %d minutes"
        $ = "BD started at %s"
        $ = "decyphering failed on bd"

    condition:
        any of them
}// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2021, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"

private rule IIS_Native_Module {
    meta:
        description = "Signature to match an IIS native module (clean or malicious)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $e1 = "This module subscribed to event"
        $e2 = "CHttpModule::OnBeginRequest"
        $e3 = "CHttpModule::OnPostBeginRequest"
        $e4 = "CHttpModule::OnAuthenticateRequest"
        $e5 = "CHttpModule::OnPostAuthenticateRequest"
        $e6 = "CHttpModule::OnAuthorizeRequest"
        $e7 = "CHttpModule::OnPostAuthorizeRequest"
        $e8 = "CHttpModule::OnResolveRequestCache"
        $e9 = "CHttpModule::OnPostResolveRequestCache"
        $e10 = "CHttpModule::OnMapRequestHandler"
        $e11 = "CHttpModule::OnPostMapRequestHandler"
        $e12 = "CHttpModule::OnAcquireRequestState"
        $e13 = "CHttpModule::OnPostAcquireRequestState"
        $e14 = "CHttpModule::OnPreExecuteRequestHandler"
        $e15 = "CHttpModule::OnPostPreExecuteRequestHandler"
        $e16 = "CHttpModule::OnExecuteRequestHandler"
        $e17 = "CHttpModule::OnPostExecuteRequestHandler"
        $e18 = "CHttpModule::OnReleaseRequestState"
        $e19 = "CHttpModule::OnPostReleaseRequestState"
        $e20 = "CHttpModule::OnUpdateRequestCache"
        $e21 = "CHttpModule::OnPostUpdateRequestCache"
        $e22 = "CHttpModule::OnLogRequest"
        $e23 = "CHttpModule::OnPostLogRequest"
        $e24 = "CHttpModule::OnEndRequest"
        $e25 = "CHttpModule::OnPostEndRequest"
        $e26 = "CHttpModule::OnSendResponse"
        $e27 = "CHttpModule::OnMapPath"
        $e28 = "CHttpModule::OnReadEntity"
        $e29 = "CHttpModule::OnCustomRequestNotification"
        $e30 = "CHttpModule::OnAsyncCompletion"
        $e31 = "CGlobalModule::OnGlobalStopListening"
        $e32 = "CGlobalModule::OnGlobalCacheCleanup"
        $e33 = "CGlobalModule::OnGlobalCacheOperation"
        $e34 = "CGlobalModule::OnGlobalHealthCheck"
        $e35 = "CGlobalModule::OnGlobalConfigurationChange"
        $e36 = "CGlobalModule::OnGlobalFileChange"
        $e37 = "CGlobalModule::OnGlobalApplicationStart"
        $e38 = "CGlobalModule::OnGlobalApplicationResolveModules"
        $e39 = "CGlobalModule::OnGlobalApplicationStop"
        $e40 = "CGlobalModule::OnGlobalRSCAQuery"
        $e41 = "CGlobalModule::OnGlobalTraceEvent"
        $e42 = "CGlobalModule::OnGlobalCustomNotification"
        $e43 = "CGlobalModule::OnGlobalThreadCleanup"
        $e44 = "CGlobalModule::OnGlobalApplicationPreload"    
    
    condition:
        uint16(0) == 0x5A4D and pe.exports("RegisterModule") and any of ($e*)
}

rule IIS_Group01_IISRaid {

    meta:
        description = "Detects Group 1 native IIS malware family (IIS-Raid derivates)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "cmd.exe" ascii wide
        $s2 = "CMD"
        $s3 = "PIN"
        $s4 = "INJ"
        $s5 = "DMP"
        $s6 = "UPL"
        $s7 = "DOW"
        $s8 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
        
        $p1 = "C:\\Windows\\Temp\\creds.db"
        $p2 = "C:\\Windows\\Temp\\thumbs.db"
        $p3 = "C:\\Windows\\Temp\\AAD30E0F.tmp"
        $p4 = "X-Chrome-Variations"
        $p5 = "X-Cache"
        $p6 = "X-Via"
        $p7 = "COM_InterProt"
        $p8 = "X-FFEServer"
        $p9 = "X-Content-Type-Options"
        $p10 = "Strict-Transport-Security"
        $p11 = "X-Password"
        $p12 = "XXXYYY-Ref"
        $p13 = "X-BLOG"
        $p14 = "X-BlogEngine"

    condition:
        IIS_Native_Module and 3 of ($s*) and any of ($p*)
}

rule IIS_Group02 {

    meta:
        description = "Detects Group 2 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "HttpModule.pdb" ascii wide
        $s2 = "([\\w+%]+)=([^&]*)"
        $s3 = "([\\w+%]+)=([^!]*)"
        $s4 = "cmd.exe"
        $s5 = "C:\\Users\\Iso\\Documents\\Visual Studio 2013\\Projects\\IIS 5\\x64\\Release\\Vi.pdb" ascii wide
        $s6 = "AVRSAFunction"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group03 {

    meta:
        description = "Detects Group 3 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "IIS-Backdoor.dll" 
        $s2 = "CryptStringToBinaryA"
        $s3 = "CreateProcessA"
        $s4 = "X-Cookie"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group04_RGDoor {

    meta:
        description = "Detects Group 4 native IIS malware family (RGDoor)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        reference = "https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $i1 = "RGSESSIONID="
        $s2 = "upload$"
        $s3 = "download$"
        $s4 = "cmd$"
        $s5 = "cmd.exe"

    condition:
        IIS_Native_Module and ($i1 or all of ($s*))
}

rule IIS_Group05_IIStealer {

    meta:
        description = "Detects Group 5 native IIS malware family (IIStealer)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "tojLrGzFMbcDTKcH" ascii wide
        $s2 = "4vUOj3IutgtrpVwh" ascii wide
        $s3 = "SoUnRCxgREXMu9bM" ascii wide
        $s4 = "9Zr1Z78OkgaXj1Xr" ascii wide
        $s5 = "cache.txt" ascii wide
        $s6 = "/checkout/checkout.aspx" ascii wide
        $s7 = "/checkout/Payment.aspx" ascii wide
        $s8 = "/privacy.aspx"
        $s9 = "X-IIS-Data"
        $s10 = "POST"

        // string stacking of "/checkout/checkout.aspx"
        $s11 = {C7 ?? CF 2F 00 63 00 C7 ?? D3 68 00 65 00 C7 ?? D7 63 00 6B 00 C7 ?? DB 6F 00 75 00 C7 ?? DF 74 00 2F 00 C7 ?? E3 63 00 68 00 C7 ?? E7 65 00 63 00 C7 ?? EB 6B 00 6F 00 C7 ?? EF 75 00 74 00 C7 ?? F3 2E 00 61 00 C7 ?? F7 73 00 70 00 C7 ?? FB 78 00 00 00}

        // string stacking of "/privacy.aspx"
        $s12 = {C7 ?? AF 2F 00 70 00 C7 ?? B3 72 00 69 00 C7 ?? B7 76 00 61 00 C7 ?? BB 63 00 79 00 C7 ?? BF 2E 00 61 00 C7 ?? C3 73 00 70 00 C7 ?? C7 78 00 00 00}

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group06_ISN {

    meta:
        description = "Detects Group 6 native IIS malware family (ISN)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-curious-case-of-the-malicious-iis-module/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "isn7 config reloaded"
        $s2 = "isn7 config NOT reloaded, not found or empty"
        $s3 = "isn7 log deleted"
        $s4 = "isn7 log not deleted, ERROR 0x%X"
        $s5 = "isn7 log NOT found"
        $s6 = "isn_reloadconfig"
        $s7 = "D:\\soft\\Programming\\C++\\projects\\isapi\\isn7"
        $s8 = "get POST failed %d"
        $s9 = "isn7.dll"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group07_IISpy {

    meta:
        description = "Detects Group 7 native IIS malware family (IISpy)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "/credential/username"
        $s2 = "/credential/password"
        $s3 = "/computer/domain"
        $s4 = "/computer/name"
        $s5 = "/password"
        $s6 = "/cmd"
        $s7 = "%.8s%.8s=%.8s%.16s%.8s%.16s"
        $s8 = "ImpersonateLoggedOnUser"
        $s9 = "WNetAddConnection2W"

        $t1 = "X-Forwarded-Proto"
        $t2 = "Sec-Fetch-Mode"
        $t3 = "Sec-Fetch-Site"
        $t4 = "Cookie"

        // PNG IEND
        $t5 = {49 45 4E 44 AE 42 60 82}

        // PNG HEADER
        $t6 = {89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52}

    condition:
        IIS_Native_Module and 2 of ($s*) and any of ($t*)
}

rule IIS_Group08 {

    meta:
        description = "Detects Group 8 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $i1 = "FliterSecurity.dll"
        $i2 = "IIS7NativeModule.dll"
        $i3 = "Ver1.0."

        $s1 = "Cmd"
        $s2 = "Realy path : %s"
        $s3 = "Logged On Users : %d"
        $s4 = "Connect OK!"
        $s5 = "You are fucked!"
        $s6 = "Shit!Error"
        $s7 = "Where is the God!!"
        $s8 = "Shit!Download False!"
        $s9 = "Good!Run OK!"
        $s10 = "Shit!Run False!"
        $s11 = "Good!Download OK!"
        $s12 = "[%d]safedog"
        $s13 = "ed81bfc09d069121"
        $s14 = "a9478ef01967d190"
        $s15 = "af964b7479e5aea2"
        $s16 = "1f9e6526bea65b59"
        $s17 = "2b9e9de34f782d31"
        $s18 = "33cc5da72ac9d7bb"
        $s19 = "b1d71f4c2596cd55"
        $s20 = "101fb9d9e86d9e6c"
    
    condition:
        IIS_Native_Module and 1 of ($i*) and 3 of ($s*)
}

rule IIS_Group09 {

    meta:
        description = "Detects Group 9 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $i1 = "FliterSecurity.dll"
        $i2 = {56565656565656565656565656565656}
        $i3 = "app|hot|alp|svf|fkj|mry|poc|doc|20" xor
        $i4 = "yisouspider|yisou|soso|sogou|m.sogou|sogo|sogou|so.com|baidu|bing|360" xor
        $i5 = "baidu|m.baidu|soso|sogou|m.sogou|sogo|sogou|so.com|google|youdao" xor
        $i6 = "118|abc|1go|evk" xor

        $s1 = "AVCFuckHttpModuleFactory"
        $s2 = "X-Forward"
        $s3 = "fuck32.dat"
        $s4 = "fuck64.dat"
        $s5 = "&ipzz1="
        $s6 = "&ipzz2="
        $s7 = "&uuu="

        $s8 = "http://20.3323sf.c" xor
        $s9 = "http://bj.whtjz.c" xor
        $s10 = "http://bj2.wzrpx.c" xor
        $s11 = "http://cs.whtjz.c" xor
        $s12 = "http://df.e652.c" xor
        $s13 = "http://dfcp.yyphw.c" xor
        $s14 = "http://es.csdsx.c" xor
        $s15 = "http://hz.wzrpx.c" xor
        $s16 = "http://id.3323sf.c" xor
        $s17 = "http://qp.008php.c" xor
        $s18 = "http://qp.nmnsw.c" xor
        $s19 = "http://sc.300bt.c" xor
        $s20 = "http://sc.wzrpx.c" xor
        $s21 = "http://sf2223.c" xor
        $s22 = "http://sx.cmdxb.c" xor
        $s23 = "http://sz.ycfhx.c" xor
        $s24 = "http://xpq.0660sf.c" xor
        $s25 = "http://xsc.b1174.c" xor

    condition:
        IIS_Native_Module and any of ($i*) and 3 of ($s*)
}

rule IIS_Group10 {

    meta:
        description = "Detects Group 10 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "IIS7.dll"
        $s2 = "<title>(.*?)title(.*?)>"
        $s3 = "<meta(.*?)name(.*?)=(.*?)keywords(.*?)>"
        $s4 = "<meta(.*?)name(.*?)=(.*?)description(.*?)>"
        $s5 = "js.breakavs.co"
        $s6 = "&#24494;&#20449;&#32676;&#45;&#36187;&#36710;&#80;&#75;&#49;&#48;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#95;&#24184;&#36816;&#39134;&#33351;&#95;&#24184;&#36816;&#50;&#56;&#32676;"
        $s7 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#112;&#107;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#32676;&#44;"
        $s8 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#21495;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;"

        $e1 = "Baiduspider"
        $e2 = "Sosospider"
        $e3 = "Sogou web spider"
        $e4 = "360Spider"
        $e5 = "YisouSpider"
        $e6 = "sogou.com"
        $e7 = "soso.com"
        $e8 = "uc.cn"
        $e9 = "baidu.com"
        $e10 = "sm.cn"

    condition:
        IIS_Native_Module and 2 of ($e*) and 3 of ($s*)
}

rule IIS_Group11 {

    meta:
        description = "Detects Group 11 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "DnsQuery_A"
        $s2 = "&reurl="
        $s3 = "&jump=1"

        // encrypted "HTTP_cmd" (SUB 2)
        $s4 = "JVVRaeof" 

        // encrypted "lanke88" (SUB 2)
        $s5 = "ncpmg::0"

        // encrypted "xinxx.allsoulu[.]com" (SUB 2)
        $s6 = "zkpzz0cnnuqwnw0eqo" 

        // encrypted "http://www.allsoulu[.]com/1.php?cmdout=" (SUB 2)
        $s7 = "jvvr<11yyy0cnnuqwnw0eqo130rjrAeofqwv?"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group12 {

    meta:
        description = "Detects Group 12 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "C:\\inetpub\\temp\\IIS Temporary Compressed Files\\"
        $s2 = "F5XFFHttpModule.dll"
        $s3 = "gtest_redir"
        $s4 = "\\cmd.exe" nocase
        $s5 = "iuuq;00" // encrypted "http://" (ADD 1)
        $s6 = "?xhost="
        $s7 = "&reurl="
        $s8 = "?jump=1"
        $s9 = "app|zqb"
        $s10 = "ifeng|ivc|sogou|so.com|baidu|google|youdao|yahoo|bing|118114|biso|gougou|sooule|360|sm|uc"
        $s11 = "sogou|so.com|baidu|google|youdao|yahoo|bing|gougou|sooule|360|sm.cn|uc"
        $s12 = "Hotcss/|Hotjs/"
        $s13 = "HotImg/|HotPic/"
        $s14 = "msf connect error !!"
        $s15 = "download ok !!"
        $s16 = "download error !! "
        $s17 = "param error !!"
        $s18 = "Real Path: "
        $s19 = "unknown cmd !"

        // hardcoded hash values
        $b1 = {15 BD 01 2E [-] 5E 40 08 97 [-] CF 8C BE 30 [-] 28 42 C6 3B}
        $b2 = {E1 0A DC 39 [-] 49 BA 59 AB [-] BE 56 E0 57 [-] F2 0F 88 3E}

    condition:
        IIS_Native_Module and 5 of them
}

rule IIS_Group13_IISerpent {

    meta:
        description = "Detects Group 13 native IIS malware family (IISerpent)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "/mconfig/lunlian.txt"
        $s2 = "http://sb.qrfy.ne"
        $s3 = "folderlinkpath"
        $s4 = "folderlinkcount"
        $s5 = "onlymobilespider"
        $s6 = "redirectreferer"
        $s7 = "loadSuccessfull : "
        $s8 = "spider"
        $s9 = "<a href="
        $s11 = "?ReloadModuleConfig=1"
        $s12 = "?DisplayModuleConfig=1"

    condition:
        IIS_Native_Module and 5 of them
}

rule IIS_Group14 {

    meta:
        description = "Detects Group 14 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $i1 = "agent-self: %s"
        $i2 = "/utf.php?key="
        $i3 = "/self.php?v="
        $i4 = "<script type=\"text/javascript\" src=\"//speed.wlaspsd.co"
        $i5 = "now.asmkpo.co"

        $s1 = "Baiduspider"
        $s2 = "360Spider"
        $s3 = "Sogou"
        $s4 = "YisouSpider"
        $s6 = "HTTP_X_FORWARDED_FOR"


    condition:
        IIS_Native_Module and 2 of ($i*) or 5 of them
}// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2017, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
import "pe"

rule generic_carbon
{
  meta:
    author      = "ESET Research"
    date        = "2017-03-30"
    description = "Turla Carbon malware"
    reference   = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

  strings:
    $s1 = "ModStart"
    $t1 = "STOP|OK"
    $t2 = "STOP|KILL"

  condition:
    (uint16(0) == 0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}

rule carbon_metadata
{
  meta:
    author      = "ESET Research"
    date        = "2017-03-30"
    description = "Turla Carbon malware"
    reference   = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

   condition:
      (pe.version_info["InternalName"] contains "SERVICE.EXE" or
       pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or
       pe.version_info["InternalName"] contains "MSXIML.DLL")
       and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2021, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"

private rule InvisiMole_Blob {
    meta:
        description = "Detects InvisiMole blobs by magic values"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $magic_old_32 = {F9 FF D0 DE}
        $magic_old_64 = {64 FF D0 DE}
        $magic_new_32 = {86 DA 11 CE}
        $magic_new_64 = {64 DA 11 CE}

    condition:
        ($magic_old_32 at 0) or ($magic_old_64 at 0) or ($magic_new_32 at 0) or ($magic_new_64 at 0)
}

rule apt_Windows_InvisiMole_Logs {
    meta:
        description = "Detects log files with collected created by InvisiMole's RC2CL backdoor"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    condition:
        uint32(0) == 0x08F1CAA1 or
        uint32(0) == 0x08F1CAA2 or
        uint32(0) == 0x08F1CCC0 or
        uint32(0) == 0x08F2AFC0 or
        uint32(0) == 0x083AE4DF or
        uint32(0) == 0x18F2CBB1 or
        uint32(0) == 0x1900ABBA or
        uint32(0) == 0x24F2CEA1 or
        uint32(0) == 0xDA012193 or
        uint32(0) == 0xDA018993 or
        uint32(0) == 0xDA018995 or
        uint32(0) == 0xDD018991
}

rule apt_Windows_InvisiMole_SFX_Dropper {

    meta:
        description = "Detects trojanized InvisiMole files: patched RAR SFX droppers with added InvisiMole blobs (config encrypted XOR 2A at the end of a file)"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $encrypted_config = {5F 59 4F 58 19 18 04 4E 46 46 2A 5D 59 5A 58 43 44 5E 4C 7D 2A 0F 2A 59 2A 78 2A 4B 2A 58 2A 0E 2A 6F 2A 72 2A 4B 2A 0F 2A 4E 2A 04 2A 0F 2A 4E 2A 76 2A 0F 2A 79 2A 2A 2A 79 42 4F 46 46 6F 52 4F 49 5F 5E 4F 7D 2A 79 42 4F 46 46 19 18 04 4E 46 46 2A 7C 43 58 5E 5F 4B 46 6B 46 46 45 49 2A 66 45 4B 4E 66 43 48 58 4B 58 53 6B}

    condition:
        uint16(0) == 0x5A4D and $encrypted_config
}

rule apt_Windows_InvisiMole_CPL_Loader {
    meta:
        description = "CPL loader"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "WScr%steObject(\"WScr%s.Run(\"::{20d04fe0-3a%s30309d}\\\\::{21EC%sDD-08002B3030%s\", 0);"
        $s2 = "\\Control.js" wide
        $s3 = "\\Control Panel.lnk" wide
        $s4 = "FPC 3.0.4 [2019/04/13] for x86_64 - Win64"
        $s5 = "FPC 3.0.4 [2019/04/13] for i386 - Win32"
        $s6 = "imageapplet.dat" wide
        $s7 = "wkssvmtx"

    condition:
        uint16(0) == 0x5A4D and (3 of them)
}

rule apt_Windows_InvisiMole_Wrapper_DLL {
    meta:
        description = "Detects InvisiMole wrapper DLL with embedded RC2CL and RC2FM backdoors, by export and resource names"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/2018/06/07/invisimole-equipped-spyware-undercover/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    condition:
        pe.exports("GetDataLength") and
        for any y in (0..pe.number_of_resources - 1): (
            pe.resources[y].type == pe.RESOURCE_TYPE_RCDATA and pe.resources[y].name_string == "R\x00C\x002\x00C\x00L\x00"
        ) and
        for any y in (0..pe.number_of_resources - 1): (
            pe.resources[y].type == pe.RESOURCE_TYPE_RCDATA and pe.resources[y].name_string == "R\x00C\x002\x00F\x00M\x00"
        )
}

rule apt_Windows_InvisiMole_DNS_Downloader {

    meta:
        description = "InvisiMole DNS downloader"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $d = "DnsQuery_A"

        $s1 = "Wireshark-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}" xor
        $s2 = "AddIns\\" ascii wide xor
        $s3 = "pcornomeex." xor
        $s4 = "weriahsek.rxe" xor
        $s5 = "dpmupaceex." xor
        $s6 = "TCPViewClass" xor
        $s7 = "PROCMON_WINDOW_CLASS" xor
        $s8 = "Key%C"
        $s9 = "AutoEx%C" xor
        $s10 = "MSO~"
        $s11 = "MDE~"
        $s12 = "DNS PLUGIN, Step %d" xor
        $s13 = "rundll32.exe \"%s\",StartUI"

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and $d and 5 of ($s*)
}

rule apt_Windows_InvisiMole_RC2CL_Backdoor {

    meta:
        description = "InvisiMole RC2CL backdoor"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "RC2CL" wide

        $s2 = "hp12KsNh92Dwd" wide
        $s3 = "ZLib package %s: files: %d, total size: %d" wide
        $s4 = "\\Un4seen" wide
        $s5 = {9E 01 3A AD} // encryption key

        $s6 = "~mrc_" wide
        $s7 = "~src_" wide
        $s8 = "~wbc_" wide
        $s9 = "zdf_" wide
        $s10 = "~S0PM" wide
        $s11 = "~A0FM" wide
        $s12 = "~70Z63\\" wide
        $s13 = "~E070C" wide
        $s14 = "~N031E" wide

        $s15 = "%szdf_%s.data" wide
        $s16 = "%spicture.crd" wide
        $s17 = "%s70zf_%s.cab" wide
        $s18 = "%spreview.crd" wide

        $s19 = "Value_Bck" wide
        $s20 = "Value_WSFX_ZC" wide
        $s21 = "MachineAccessStateData" wide
        $s22 = "SettingsSR2" wide

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and 5 of ($s*)
}

rule apt_Windows_InvisiMole {

    meta:
        description = "InvisiMole magic values, keys and strings"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "CryptProtectData"
        $s2 = "CryptUnprotectData"
        $s3 = {9E 01 3A AD}
        $s4 = "GET /getversion2a/%d%.2X%.2X/U%sN HTTP/1.1"
        $s5 = "PULSAR_LOADER.dll"

        /*
        cmp reg, 0DED0FFF9h
        */
        $check_magic_old_32 = {3? F9 FF D0 DE}

        /*
        cmp reg, 0DED0FF64h
        */
        $check_magic_old_64 = {3? 64 FF D0 DE}

        /*
        cmp dword ptr [reg], 0CE11DA86h
        */
        $check_magic_new_32 = {81 3? 86 DA 11 CE}

        /*
        cmp dword ptr [reg], 0CE11DA64h
        */
        $check_magic_new_64 = {81 3? 64 DA 11 CE}

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and (any of ($check_magic*)) and (2 of ($s*))
}

rule apt_Windows_InvisiMole_C2 {

    meta:
        description = "InvisiMole C&C servers"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "46.165.220.228" ascii wide
        $s2 = "80.255.3.66" ascii wide
        $s3 = "85.17.26.174" ascii wide
        $s4 = "185.193.38.55" ascii wide
        $s5 = "194.187.249.157"  ascii wide
        $s6 = "195.154.255.211"  ascii wide
        $s7 = "153.re"  ascii wide fullword
        $s8 = "adstat.red"  ascii wide
        $s9 = "adtrax.net"  ascii wide
        $s10 = "akamai.sytes.net"  ascii wide
        $s11 = "amz-eu401.com"  ascii wide
        $s12 = "blabla234342.sytes.net"  ascii wide
        $s13 = "mx1.be"  ascii wide fullword
        $s14 = "statad.de"  ascii wide
        $s15 = "time.servehttp.com"  ascii wide
        $s16 = "upd.re"  ascii wide fullword
        $s17 = "update.xn--6frz82g"  ascii wide
        $s18 = "updatecloud.sytes.net"  ascii wide
        $s19 = "updchecking.sytes.net"  ascii wide
        $s20 = "wlsts.net"  ascii wide
        $s21 = "ro2.host"  ascii wide fullword
        $s22 = "2ld.xyz"  ascii wide fullword
        $s23 = "the-haba.com"  ascii wide
        $s24 = "82.202.172.134"  ascii wide
        $s25 = "update.xn--6frz82g"  ascii wide

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and $s21 and any of them
}
// Keydnap packer yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


rule keydnap_downloader
{
    meta:
        description = "OSX/Keydnap Downloader"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $ = "icloudsyncd"
        $ = "killall Terminal"
        $ = "open %s"
    
    condition:
        2 of them
}

rule keydnap_backdoor_packer
{
    meta:
        description = "OSX/Keydnap packed backdoor"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $upx_string = "This file is packed with the UPX"
        $packer_magic = "ASS7"
        $upx_magic = "UPX!"
        
    condition:
        $upx_string and $packer_magic and not $upx_magic
}

rule keydnap_backdoor
{
    meta:
        description = "Unpacked OSX/Keydnap backdoor"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $ = "api/osx/get_task"
        $ = "api/osx/cmd_executed"
        $ = "Loader-"
        $ = "u2RLhh+!LGd9p8!ZtuKcN"
        $ = "com.apple.iCloud.sync.daemon"
    condition:
        2 of them
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2020, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule kobalos
{
    meta:
        description = "Kobalos malware"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
        $password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
        $rsa_512_mod_header = { 10 11 02 00 09 02 00 }
        $strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

    condition:
        any of them
}

rule kobalos_ssh_credential_stealer {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

    condition:
        any of them
}
// Linux/Moose yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015-2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
private rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule moose_1
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2015/04/21"
        Description = "Linux/Moose malware"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/05/Dissecting-LinuxMoose.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s0 = "Status: OK"
        $s1 = "--scrypt"
        $s2 = "stratum+tcp://"
        $s3 = "cmd.so"
        $s4 = "/Challenge"
        $s7 = "processor"
        $s9 = "cpu model"
        $s21 = "password is wrong"
        $s22 = "password:"
        $s23 = "uthentication failed"
        $s24 = "sh"
        $s25 = "ps"
        $s26 = "echo -n -e "
        $s27 = "chmod"
        $s28 = "elan2"
        $s29 = "elan3"
        $s30 = "chmod: not found"
        $s31 = "cat /proc/cpuinfo"
        $s32 = "/proc/%s/cmdline"
        $s33 = "kill %s"

    condition:
        is_elf and all of them
}

rule moose_2
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2016/10/02"
        Description = "Linux/Moose malware active since September 2015"
        Reference   = "http://www.welivesecurity.com/2016/11/02/linuxmoose-still-breathing/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "Modules are loaded"
        $s2 = "--scrypt"
        $s3 = "http://"
        $s4 = "https://"
        $s5 = "processor "
        $s6 = "cpu model "
        $s7 = "Host: www.challpok.cn"
        $s8 = "Cookie: PHPSESSID=%s; nhash=%s; chash=%s"
        $s9 = "fail!"
        $s10 = "H3lL0WoRlD"
        $s11 = "crondd"
        $s12 = "cat /proc/cpuinfo"
        $s13 = "Set-Cookie: PHPSESSID="
        $s14 = "Set-Cookie: LP="
        $s15 = "Set-Cookie: WL="
        $s16 = "Set-Cookie: CP="
        $s17 = "Loading modules..."
        $s18 = "-nobg"

    condition:
        is_elf and 5 of them
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2023, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule mozi_killswitch
{
    meta:
        description = "Mozi botnet kill switch"
        author = "Ivan Besina"
        date = "2023-09-29"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $iptables1 = "iptables -I INPUT  -p tcp --destination-port 7547 -j DROP"
        $iptables2 = "iptables -I OUTPUT -p tcp --sport 30005 -j DROP"
        $haha = "/haha"
        $networks = "/usr/networks"

    condition:
        all of them and filesize < 500KB
}
// Mumblehard packer yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule mumblehard_packer
{
    meta:
        description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
        author = "Marc-Etienne M.Léveillé"
        date = "2015-04-07"
        reference = "http://www.welivesecurity.com"
        version = "1"

    strings:
        $decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-6]  (56 5f |  89 F7)
                     39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
                     00 31 db 43 ac 30 d8 aa 43 e2 e2 }
    condition:
        $decrypt
}// Operation Potao yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
private rule PotaoDecoy
{
    strings:
        $mz = { 4d 5a }
        $str1 = "eroqw11"
        $str2 = "2sfsdf"
        $str3 = "RtlDecompressBuffer"
        $wiki_str = "spanned more than 100 years and ruined three consecutive" wide

        $old_ver1 = {53 68 65 6C 6C 33 32 2E 64 6C 6C 00 64 61 66 73 72 00 00 00 64 61 66 73 72 00 00 00 64 6F 63 (00 | 78)}
        $old_ver2 = {6F 70 65 6E 00 00 00 00 64 6F 63 00 64 61 66 73 72 00 00 00 53 68 65 6C 6C 33 32 2E 64 6C 6C 00}       
    condition:
        ($mz at 0) and ( (all of ($str*)) or any of ($old_ver*) or $wiki_str )
}
private rule PotaoDll
{
    strings:
        $mz = { 4d 5a }
        
        $dllstr1 = "?AVCncBuffer@@"
        $dllstr2 = "?AVCncRequest@@"
        $dllstr3 = "Petrozavodskaya, 11, 9"
        $dllstr4 = "_Scan@0"
        $dllstr5 = "\x00/sync/document/"
        $dllstr6 = "\\temp.temp"
        
        $dllname1 = "node69MainModule.dll"
        $dllname2 = "node69-main.dll"
        $dllname3 = "node69MainModuleD.dll"
        $dllname4 = "task-diskscanner.dll"
        $dllname5 = "\x00Screen.dll"
        $dllname6 = "Poker2.dll"        
        $dllname7 = "PasswordStealer.dll"
        $dllname8 = "KeyLog2Runner.dll" 
        $dllname9 = "GetAllSystemInfo.dll"          
        $dllname10 = "FilePathStealer.dll"          
    condition:
        ($mz at 0) and (any of ($dllstr*) and any of ($dllname*))
}
private rule PotaoUSB
{
    strings:
        $mz = { 4d 5a }
        
        $binary1 = { 33 C0 8B C8 83 E1 03 BA ?? ?? ?? 00 2B D1 8A 0A 32 88 ?? ?? ?? 00 2A C8 FE C9 88 88 ?? ?? ?? 00 40 3D ?? ?? 00 00 7C DA C3 }
        $binary2 = { 55 8B EC 51 56 C7 45 FC 00 00 00 00 EB 09 8B 45 FC 83 C0 01 89 45 FC 81 7D FC ?? ?? 00 00 7D 3D 8B 4D FC 0F BE 89 ?? ?? ?? 00 8B 45 FC 33 D2 BE 04 00 00 00 F7 F6 B8 03 00 00 00 2B C2 0F BE 90 ?? ?? ?? 00 33 CA 2B 4D FC 83 E9 01 81 E1 FF 00 00 00 8B 45 FC 88 88 ?? ?? ?? 00 EB B1 5E 8B E5 5D C3}
    condition:
        ($mz at 0) and any of ($binary*)
}
private rule PotaoSecondStage
{
    strings:
        $mz = { 4d 5a }
        // hash of CryptBinaryToStringA and CryptStringToBinaryA
        $binary1 = {51 7A BB 85 [10-180] E8 47 D2 A8}
        // old hash of CryptBinaryToStringA and CryptStringToBinaryA
        $binary2 = {5F 21 63 DD [10-30] EC FD 33 02}
        $binary3 = {CA 77 67 57 [10-30] BA 08 20 7A}
        
        $str1 = "?AVCrypt32Import@@"
        $str2 = "%.5llx"
    condition:
        ($mz at 0) and any of ($binary*) and any of ($str*)
}
rule Potao
{
    meta:
        Author      = "Anton Cherepanov"
        Date        = "2015/07/29"
        Description = "Operation Potao"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/07/Operation-Potao-Express_final_v2.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "threatintel@eset.com"
        License = "BSD 2-Clause"
    condition:
        PotaoDecoy or PotaoDll or PotaoUSB or PotaoSecondStage
}
// Operation Groundbait yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

private rule PrikormkaDropper
{
    strings:
        $mz = { 4D 5A }

        $kd00 = "KDSTORAGE" wide
        $kd01 = "KDSTORAGE_64" wide
        $kd02 = "KDRUNDRV32" wide
        $kd03 = "KDRAR" wide

        $bin00 = {69 65 04 15 00 14 1E 4A 16 42 08 6C 21 61 24 0F}
        $bin01 = {76 6F 05 04 16 1B 0D 5E 0D 42 08 6C 20 45 18 16}
        $bin02 = {4D 00 4D 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5F 00 73 00 76 00 67 00}

        $inj00 = "?AVCinj2008Dlg@@" ascii
        $inj01 = "?AVCinj2008App@@" ascii
    condition:
        ($mz at 0) and ((any of ($bin*)) or (3 of ($kd*)) or (all of ($inj*)))
}

private rule PrikormkaModule
{
    strings:
        $mz = { 4D 5A }

        // binary
        $str00 = {6D 70 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str01 = {68 6C 70 75 63 74 66 2E 64 6C 6C 00 43 79 63 6C 65}
        $str02 = {00 6B 6C 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str03 = {69 6F 6D 75 73 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67}
        $str04 = {61 74 69 6D 6C 2E 64 6C 6C 00 4B 69 63 6B 49 6E 50 6F 69 6E 74}
        $str05 = {73 6E 6D 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
        $str06 = {73 63 72 73 68 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}

        // encrypted
        $str07 = {50 52 55 5C 17 51 58 17 5E 4A}
        $str08 = {60 4A 55 55 4E 53 58 4B 17 52 57 17 5E 4A}
        $str09 = {55 52 5D 4E 5B 4A 5D 17 51 58 17 5E 4A}
        $str10 = {60 4A 55 55 4E 61 17 51 58 17 5E 4A}
        $str11 = {39 5D 17 1D 1C 0A 3C 57 59 3B 1C 1E 57 58 4C 54 0F}

        // mutex
        $str12 = "ZxWinDeffContex" ascii wide
        $str13 = "Paramore756Contex43" wide
        $str14 = "Zw_&one@ldrContext43" wide

        // other
        $str15 = "A95BL765MNG2GPRS"

        // dll names
        $str16 = "helpldr.dll" wide fullword
        $str17 = "swma.dll" wide fullword
        $str18 = "iomus.dll" wide fullword
        $str19 = "atiml.dll"  wide fullword
        $str20 = "hlpuctf.dll" wide fullword
        $str21 = "hauthuid.dll" ascii wide fullword

        // rbcon
        $str22 = "[roboconid][%s]" ascii fullword
        $str23 = "[objectset][%s]" ascii fullword
        $str24 = "rbcon.ini" wide fullword

        // files and logs
        $str25 = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
        $str26 = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword

        // pdb strings
        $str27 = ":\\!PROJECTS!\\Mina\\2015\\" ascii
        $str28 = "\\PZZ\\RMO\\" ascii
        $str29 = ":\\work\\PZZ" ascii
        $str30 = "C:\\Users\\mlk\\" ascii
        $str31 = ":\\W o r k S p a c e\\" ascii
        $str32 = "D:\\My\\Projects_All\\2015\\" ascii
        $str33 = "\\TOOLS PZZ\\Bezzahod\\" ascii

    condition:
        ($mz at 0) and (any of ($str*))
}

private rule PrikormkaEarlyVersion
{
    strings:
        $mz = { 4D 5A }

        $str00 = "IntelRestore" ascii fullword
        $str01 = "Resent" wide fullword
        $str02 = "ocp8.1" wide fullword
        $str03 = "rsfvxd.dat" ascii fullword
        $str04 = "tsb386.dat" ascii fullword
        $str05 = "frmmlg.dat" ascii fullword
        $str06 = "smdhost.dll" ascii fullword
        $str07 = "KDLLCFX" wide fullword
        $str08 = "KDLLRUNDRV" wide fullword
    condition:
        ($mz at 0) and (2 of ($str*))
}

rule Prikormka
{
    meta:
        Author      = "Anton Cherepanov"
        Date        = "2016/05/10"
        Description = "Operation Groundbait"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "threatintel@eset.com"
        License = "BSD 2-Clause"
    condition:
        PrikormkaDropper or PrikormkaModule or PrikormkaEarlyVersion
}
// Linux/Rakos yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


rule linux_rakos
{
    meta:
        description = "Linux/Rakos.A executable"
        author = "Peter Kálnai"
        date = "2016-12-13"
        reference = "http://www.welivesecurity.com/2016/12/20/new-linuxrakos-threat-devices-servers-ssh-scan/"
        version = "1"
        contact = "threatintel@eset.com"
        license = "BSD 2-Clause"


    strings:
        $ = "upgrade/vars.yaml"
        $ = "MUTTER"
        $ = "/tmp/.javaxxx"
        $ = "uckmydi"

    condition:
        3 of them
}
/*
The following rule requires YARA version >= 3.11.0
*/
import "pe"

rule RichHeaders_Lazarus_NukeSped_IconicPayloads_3CX_Q12023
{
	meta:
		description = "Rich Headers-based rule covering the IconicLoader and IconicStealer from the 3CX supply chain incident, and also payloads from the cryptocurrency campaigns from 2022-12"
		author = "ESET Research"
		date = "2023-03-31"
		hash = "3B88CDA62CDD918B62EF5AA8C5A73A46F176D18B"
		hash = "CAD1120D91B812ACAFEF7175F949DD1B09C6C21A"
		hash = "5B03294B72C0CAA5FB20E7817002C600645EB475"
		hash = "7491BD61ED15298CE5EE5FFD01C8C82A2CDB40EC"

	condition:
		pe.rich_signature.toolid(259, 30818) == 9 and
		pe.rich_signature.toolid(256, 31329) == 1 and
		pe.rich_signature.toolid(261, 30818) >= 30 and pe.rich_signature.toolid(261, 30818) <= 38  and
		pe.rich_signature.toolid(261, 29395) >= 134 and pe.rich_signature.toolid(261, 29395) <= 164  and
		pe.rich_signature.toolid(257, 29395) >= 6 and pe.rich_signature.toolid(257, 29395) <= 14 
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2019, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule skip20_sqllang_hook
{
    meta:
    author      = "Mathieu Tartare <mathieu.tartare@eset.com>"
    date        = "21-10-2019"
    description = "YARA rule to detect if a sqllang.dll version is targeted by skip-2.0. Each byte pattern corresponds to a function hooked by skip-2.0. If $1_0 or $1_1 match, it is probably targeted as it corresponds to the hook responsible for bypassing the authentication."
    reference   = "https://www.welivesecurity.com/" 
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

    strings:
        $1_0  = {ff f3 55 56 57 41 56 48 81 ec c0 01 00 00 48 c7 44 24 38 fe ff ff ff}
        $1_1  = {48 8b c3 4c 8d 9c 24 a0 00 00 00 49 8b 5b 10 49 8b 6b 18 49 8b 73 20 49 8b 7b 28 49 8b e3 41 5e c3 90 90 90 90 90 90 90 ff 25}
        $2_0  = {ff f3 55 57 41 55 48 83 ec 58 65 48 8b 04 25 30 00 00 00}
        $2_1  = {48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 ff 25}
        $3_0  = {89 4c 24 08 4c 8b dc 49 89 53 10 4d 89 43 18 4d 89 4b 20 57 48 81 ec 90 00 00 00}
        $3_1  = {4c 8d 9c 24 20 01 00 00 49 8b 5b 40 49 8b 73 48 49 8b e3 41 5f 41 5e 41 5c 5f 5d c3}
        $4_0  = {ff f5 41 56 41 57 48 81 ec 90 00 00 00 48 8d 6c 24 50 48 c7 45 28 fe ff ff ff 48 89 5d 60 48 89 75 68 48 89 7d 70 4c 89 65 78}
        $4_1  = {8b c1 48 8b 8c 24 30 02 00 00 48 33 cc}
        $5_0  = {48 8b c4 57 41 54 41 55 41 56 41 57 48 81 ec 90 03 00 00 48 c7 80 68 fd ff ff fe ff ff ff 48 89 58 18 48 89 70 20}
        $5_1  = {48 c7 80 68 fd ff ff fe ff ff ff 48 89 58 18 48 89 70 20}
        $6_0  = {44 88 4c 24 20 44 89 44 24 18 48 89 54 24 10 48 89 4c 24 08 53 56 57 41 54 41 55 41 56 41 57 48 81 ec 80 01 00 00}
        $6_1  = {48 89 4c 24 08 53 56 57 41 54 41 55 41 56 41 57 48 81 ec 80 01 00 00 48 c7 84 24 e8 00 00 00 fe ff ff ff}
        $7_0  = {08 48 89 74 24 10 57 48 83 ec 20 49 63 d8 48 8b f2 48 8b f9 45 85 c0}
        $7_1  = {20 49 63 d8 48 8b f2 48 8b f9 45 85}
        $8_0  = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [11300-] ff f5 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 70}
        $9_0  = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [40050-] 48 8b c4 55 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 60}
        $10_0 = {41 56 48 83 ec 50 48 c7 44 24 20 fe ff ff ff 48 89 5c 24 60 48 89 6c 24 68 48 89 74 24 70 48 89 7c 24 78 48 8b d9 33 ed 8b f5 89 6c}
        $10_1 = {48 8b 42 18 4c 89 90 f0 00 00 00 44 89 90 f8 00 00 00 c7 80 fc 00 00 00 1b 00 00 00 48 8b c2 c3 90 90 90}
        $11_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [40700-] 48 8b c4 55 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 60}
        $12_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [10650-] 48 8b c4 55 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 60}
        $13_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [41850-] ff f5 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 70}
        $14_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [42600-] ff f7 48 83 ec 50 48 c7 44 24 20 fe ff ff ff}

    condition:
        any of them
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2021, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"
rule SparklingGoblin_ChaCha20Loader_RichHeader
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "Rule matching ChaCha20 loaders rich header"
        date = "2021-03-30"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "09FFE37A54BC4EBEBD8D56098E4C76232F35D821"
        hash = "29B147B76BB0D9E09F7297487CB972E6A2905586"
        hash = "33F2C3DE2457B758FC5824A2B253AD7C7C2E9E37"
        hash = "45BEF297CE78521EAC6EE39E7603E18360E67C5A"
        hash = "4CEC7CDC78D95C70555A153963064F216DAE8799"
        hash = "4D4C1A062A0390B20732BA4D65317827F2339B80"
        hash = "4F6949A4906B834E83FF951E135E0850FE49D5E4"

    condition:
        pe.rich_signature.length >= 104 and pe.rich_signature.length <= 112 and
        pe.rich_signature.toolid(241, 40116) >= 5 and pe.rich_signature.toolid(241, 40116) <= 10  and
        pe.rich_signature.toolid(147, 30729) == 11 and
        pe.rich_signature.toolid(264, 24215) >= 15 and pe.rich_signature.toolid(264, 24215) <= 16 
}

rule SparklingGoblin_ChaCha20
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "SparklingGoblin ChaCha20 implementations"
        date = "2021-05-20"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
        hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
        hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
        hash = "4668302969FE122874FB2447A80378DCB671C86B"
        hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
        hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"
        hash = "91B32E030A1F286E7D502CA17E107D4BFBD7394A"

    strings:
        // 32-bits version
        $chunk_1 = {
            8B 4D ??
            56
            8B 75 ??
            57
            8B 7D ??
            8B 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 10
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 0C
            89 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 08
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 07
            89 04 BB
        }
        // 64-bits version
        $chunk_2 = {
            03 4D ??
            44 03 C0
            03 55 ??
            33 F1
            45 33 D8
            C1 C6 10
            44 33 F2
            41 C1 C3 10
            41 03 FB
            41 C1 C6 10
            45 03 E6
            41 03 DA
            44 33 CB
            44 03 EE
            41 C1 C1 10
            8B C7
            33 45 ??
            45 03 F9
            C1 C0 0C
            44 03 C0
            45 33 D8
            44 89 45 ??
            41 C1 C3 08
            41 03 FB
            44 8B C7
            44 33 C0
            41 8B C5
            33 45 ??
            C1 C0 0C
            03 C8
            41 C1 C0 07
            33 F1
            89 4D ??
            C1 C6 08
            44 03 EE
            41 8B CD
            33 C8
            41 8B C4
            33 45 ??
            C1 C0 0C
            03 D0
            C1 C1 07
            44 33 F2
            89 55 ??
            41 C1 C6 08
            45 03 E6
            41 8B D4
            33 D0
            41 8B C7
            41 33 C2
            C1 C2 07
            C1 C0 0C
            03 D8
            44 33 CB
            41 C1 C1 08
            45 03 F9
            45 8B D7
            44 33 D0
            8B 45 ??
            03 C1
            41 C1 C2 07
            44 33 C8
            89 45 ??
            41 C1 C1 10
            45 03 E1
            41 8B C4
            33 C1
            8B 4D ??
            C1 C0 0C
            03 C8
            44 33 C9
            89 4D ??
            89 4D ??
            41 C1 C1 08
            45 03 E1
            41 8B CC
            33 C8
            8B 45 ??
            C1 C1 07
            89 4D ??
            89 4D ??
            03 C2
            41 03 D8
            89 45 ??
            41 33 C3
            C1 C0 10
            44 03 F8
            41 8B CF
            33 CA
            8B 55 ??
        }
        $chunk_3 = {
            C7 45 ?? 65 78 70 61
            4C 8D 45 ??
            C7 45 ?? 6E 64 20 33
            4D 8B F9
            C7 45 ?? 32 2D 62 79
            4C 2B C1
            C7 45 ?? 74 65 20 6B
        }
        $chunk_4 = {
            0F B6 02
            0F B6 4A ??
            C1 E1 08
            0B C8
            0F B6 42 ??
            C1 E1 08
            0B C8
            0F B6 42 ??
            C1 E1 08
            0B C8
            41 89 0C 10
            48 8D 52 ??
            49 83 E9 01
        }
        // 64-bits version
        $chunk_5 = {
            03 4D ??
            44 03 C0
            03 55 ??
            33 F1
            41 33 F8
            C1 C6 10
            44 33 F2
            C1 C7 10
            44 03 DF
            41 C1 C6 10
            45 03 E6
            44 03 CB
            45 33 D1
            44 03 EE
            41 C1 C2 10
            41 8B C3
            33 45 ??
            45 03 FA
            C1 C0 0C
            44 03 C0
            41 33 F8
            44 89 45 ??
            C1 C7 08
            44 03 DF
            45 8B C3
            44 33 C0
            41 8B C5
            33 45 ??
            C1 C0 0C
            03 C8
            41 C1 C0 07
            33 F1
            89 4D ??
            C1 C6 08
            44 03 EE
            41 8B CD
            33 C8
            41 8B C4
            33 45 ??
            C1 C0 0C
            03 D0
            C1 C1 07
            44 33 F2
            89 55 ??
            41 C1 C6 08
            45 03 E6
            41 8B D4
            33 D0
            41 8B C7
            33 C3
            C1 C2 07
            C1 C0 0C
            44 03 C8
            45 33 D1
            41 C1 C2 08
            45 03 FA
            41 8B DF
            33 D8
            8B 45 ??
            03 C1
            C1 C3 07
            44 33 D0
            89 45 ??
            41 C1 C2 10
            45 03 E2
            41 8B C4
            33 C1
            8B 4D ??
            C1 C0 0C
            03 C8
            44 33 D1
            89 4D ??
            89 4D ??
            41 C1 C2 08
            45 03 E2
            41 8B CC
            33 C8
            8B 45 ??
            C1 C1 07
            89 4D ??
            89 4D ??
            03 C2
            45 03 C8
            89 45 ??
            33 C7
            C1 C0 10
            44 03 F8
            41 8B CF
            33 CA
            8B 55 ??
            C1 C1 0C
            03 D1
            8B FA
            89 55 ??
            33 F8
            89 55 ??
            8B 55 ??
            03 D3
            C1 C7 08
            44 03 FF
            41 8B C7
            33 C1
            C1 C0 07
            89 45 ??
            89 45 ??
            8B C2
            33 C6
            C1 C0 10
            44 03 D8
            41 33 DB
            C1 C3 0C
            03 D3
            8B F2
            89 55 ??
            33 F0
            41 8B C1
            41 33 C6
            C1 C6 08
            C1 C0 10
            44 03 DE
            44 03 E8
            41 33 DB
            41 8B CD
            C1 C3 07
            41 33 C8
            44 8B 45 ??
            C1 C1 0C
            44 03 C9
            45 8B F1
            44 33 F0
            41 C1 C6 08
            45 03 EE
            41 8B C5
            33 C1
            8B 4D ??
            C1 C0 07
        }

    condition:
        any of them and filesize < 450KB

}

rule SparklingGoblin_EtwEventWrite
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "SparklingGoblin EtwEventWrite patching"
        date = "2021-05-20"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
        hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
        hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
        hash = "4668302969FE122874FB2447A80378DCB671C86B"
        hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
        hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"

    strings:
        // 64-bits version
        $chunk_1 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
            83 64 24 ?? 00
            4C 8D 4C 24 ??
            BF 04 00 00 00
            48 8B C8
            8B D7
            48 8B D8
            44 8D 47 ??
            FF 15 ?? ?? ?? ??
            44 8B C7
            48 8D 54 24 ??
            48 8B CB
            E8 ?? ?? ?? ??
            44 8B 44 24 ??
            4C 8D 4C 24 ??
            8B D7
            48 8B CB
            FF 15 ?? ?? ?? ??
            48 8B 05 ?? ?? ?? ??
        }
        // 32-bits version
        $chunk_2 = {
            55
            8B EC
            51
            51
            57
            68 08 1A 41 00
            66 C7 45 ?? C2 14
            C6 45 ?? 00
            FF 15 ?? ?? ?? ??
            68 10 1A 41 00
            50
            FF 15 ?? ?? ?? ??
            83 65 ?? 00
            8B F8
            8D 45 ??
            50
            6A 40
            6A 03
            57
            FF 15 ?? ?? ?? ??
            6A 03
            8D 45 ??
            50
            57
            E8 ?? ?? ?? ??
            83 C4 0C
            8D 45 ??
            50
            FF 75 ??
            6A 03
            57
            FF 15 ?? ?? ?? ??
        }
        // 64-bits version
        $chunk_3 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
        }

    condition:
        any of them
}

rule SparklingGoblin_Mutex
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "SparklingGoblin ChaCha20 loaders mutexes"
        date = "2021-05-20"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
        hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
        hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
        hash = "4668302969FE122874FB2447A80378DCB671C86B"
        hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
        hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"

    strings:
        $mutex_1 = "kREwdFrOlvASgP4zWZyV89m6T2K0bIno"
        $mutex_2 = "v5EPQFOImpTLaGZes3Nl1JSKHku8AyCw"

    condition:
        any of them
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2018, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

private rule ssh_client : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH client (ssh)"
        author = "Marc-Etienne M.Leveille"
        email  = "leveille@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: ssh ["
        $old_version = "-L listen-port:host:port"

    condition:
        $usage or $old_version
}

private rule ssh_daemon : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
        author = "Marc-Etienne M.Leveille"
        email  = "leveille@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: sshd ["
        $old_version = "Listen on the specified port (default: 22)"

    condition:
        $usage or $old_version
}

private rule ssh_add : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH add (ssh-add)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [options] [file ...]\n"
        $log = "Could not open a connection to your authentication agent.\n"

    condition:
        $usage and $log
}

private rule ssh_agent : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH agent (ssh-agent)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [options] [command [arg ...]]"

    condition:
        $usage
}

private rule ssh_askpass : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $pass = "Enter your OpenSSH passphrase:"
        $log = "Could not grab %s. A malicious client may be eavesdropping on you"

    condition:
        $pass and $log
}

private rule ssh_keygen : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH keygen (ssh-keygen)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $pass = "Enter new passphrase (empty for no passphrase):"
        $log = "revoking certificates by key ID requires specification of a CA key"

    condition:
        $pass and $log
}

private rule ssh_keyscan : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH keyscan (ssh-keyscan)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [-46Hv] [-f file] [-p port] [-T timeout] [-t type]"

    condition:
        $usage
}

private rule ssh_binary : sshdoor {
    meta:
        description = "Signature to match any clean (or not) SSH binary"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"

    condition:
        ssh_client or ssh_daemon or ssh_add or ssh_askpass or ssh_keygen or ssh_keyscan
}

private rule stack_string {
    meta:
        description = "Rule to detect use of string-stacking"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        // single byte offset from base pointer
        $bp = /(\xC6\x45.{2}){25}/
        // dword ss with single byte offset from base pointer
        $bp_dw = /(\xC7\x45.{5}){20}/
        // 4-bytes offset from base pointer
        $bp_off = /(\xC6\x85.{5}){25}/
        // single byte offset from stack pointer
        $sp = /(\xC6\x44\x24.{2}){25}/
        // 4-bytes offset from stack pointer
        $sp_off = /(\xC6\x84\x24.{5}){25}/

    condition:
        any of them
}

rule abafar {
    meta:
        description = "Rule to detect Abafar family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log_c =  "%s:%s@%s"
        $log_d =  "%s:%s from %s"

    condition:
        ssh_binary and any of them
}

rule akiva {
    meta:
        description = "Rule to detect Akiva family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /(To|From):\s(%s\s\-\s)?%s:%s\n/

    condition:
        ssh_binary and $log
}

rule alderaan {
    meta:
        description = "Rule to detect Alderaan family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /login\s(in|at):\s(%s\s)?%s:%s\n/

    condition:
        ssh_binary and $log
}

rule ando {
    meta:
        description = "Rule to detect Ando family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "%s:%s\n"
        $s2 = "HISTFILE"
        $i = "fopen64"
        $m1 = "cat "
        $m2 = "mail -s"

    condition:
        ssh_binary and all of ($s*) and ($i or all of ($m*))
}

rule anoat {
    meta:
        description = "Rule to detect Anoat family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "%s at: %s | user: %s, pass: %s\n"

    condition:
        ssh_binary and $log
}

rule atollon {
    meta:
        description = "Rule to detect Atollon family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $f1 = "PEM_read_RSA_PUBKEY"
        $f2 = "RAND_add"
        $log = "%s:%s"
        $rand = "/dev/urandom"

    condition:
        ssh_binary and stack_string and all of them
}

rule batuu {
    meta:
        description = "Rule to detect Batuu family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $args = "ssh: ~(av[%d]: %s\n)"
        $log = "readpass: %s\n"

    condition:
        ssh_binary and any of them
}

rule bespin {
    meta:
        description = "Rule to detect Bespin family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log1 = "%Y-%m-%d %H:%M:%S"
        $log2 = "%s %s%s"
        $log3 = "[%s]"

    condition:
        ssh_binary and all of them
}

rule bonadan {
    meta:
        description = "Rule to detect Bonadan family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "g_server"
        $s2 = "mine.sock"
        $s3 = "tspeed"
        $e1 = "6106#x=%d#%s#%s#speed=%s"
        $e2 = "usmars.mynetgear.com"
        $e3 = "user=%s#os=%s#eip=%s#cpu=%s#mem=%s"

    condition:
        ssh_binary and any of them
}

rule borleias {
    meta:
        description = "Rule to detect Borleias family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "%Y-%m-%d %H:%M:%S [%s]"

    condition:
        ssh_binary and all of them
}

rule chandrila {
    meta:
        description = "Rule to detect Chandrila family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "S%s %s:%s"
        $magic = { 05 71 92 7D }

    condition:
        ssh_binary and all of them
}

rule coruscant {
    meta:
        description = "Rule to detect Coruscant family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "%s:%s@%s\n"
        $s2 = "POST"
        $s3 = "HTTP/1.1"

    condition:
        ssh_binary and all of them
}

rule crait {
    meta:
        description = "Signature to detect Crait family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $i1 = "flock"
        $i2 = "fchmod"
        $i3 = "sendto"

    condition:
        ssh_binary and 2 of them
}

rule endor {
    meta:
        description = "Rule to detect Endor family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $u = "user: %s"
        $p = "password: %s"

    condition:
        ssh_binary and $u and $p in (@u..@u+20)
}

rule jakuu {
    meta:
        description = "Rule to detect Jakuu family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        notes = "Strings can be encrypted"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $dec = /GET\s\/\?(s|c)id=/
        $enc1 = "getifaddrs"
        $enc2 = "usleep"
        $ns = "gethostbyname"
        $log = "%s:%s"
        $rc4 = { A1 71 31 17 11 1A 22 27 55 00 66 A3 10 FE C2 10 22 32 6E 95 90 84 F9 11 73 62 95 5F 4D 3B DB DC }

    condition:
        ssh_binary and $log and $ns and ($dec or all of ($enc*) or $rc4)
}

rule kamino {
    meta:
        description = "Rule to detect Kamino family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "/var/log/wtmp"
        $s2 = "/var/log/secure"
        $s3 = "/var/log/auth.log"
        $s4 = "/var/log/messages"
        $s5 = "/var/log/audit/audit.log"
        $s6 = "/var/log/httpd-access.log"
        $s7 = "/var/log/httpd-error.log"
        $s8 = "/var/log/xferlog"
        $i1 = "BIO_f_base64"
        $i2 = "PEM_read_bio_RSA_PUBKEY"
        $i3 = "srand"
        $i4 = "gethostbyname"

    condition:
        ssh_binary and 5 of ($s*) and 3 of ($i*)
}

rule kessel {
    meta:
        description = "Rule to detect Kessel family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $rc4 = "Xee5chu1Ohshasheed1u"
        $s1 = "ssh:%s:%s:%s:%s"
        $s2 = "sshkey:%s:%s:%s:%s:%s"
        $s3 = "sshd:%s:%s"
        $i1 = "spy_report"
        $i2 = "protoShellCMD"
        $i3 = "protoUploadFile"
        $i4 = "protoSendReport"
        $i5 = "tunRecvDNS"
        $i6 = "tunPackMSG"

    condition:
        ssh_binary and (2 of ($s*) or 2 of ($i*) or $rc4)
}

rule mimban {
    meta:
        description = "Rule to detect Mimban family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "<|||%s|||%s|||%d|||>"
        $s2 = />\|\|\|%s\|\|\|%s\|\|\|\d\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|</
        $s3 = "-----BEGIN PUBLIC KEY-----"
        $i1 = "BIO_f_base64"
        $i2 = "PEM_read_bio_RSA_PUBKEY"
        $i3 = "gethostbyname"

    condition:
        ssh_binary and 2 of ($s*) and 2 of ($i*)
}

rule ondaron {
    meta:
        description = "Rule to detect Ondaron family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $daemon = "user:password --> %s:%s\n"
        $client = /user(,|:)(a,)?password@host \-\-> %s(,|:)(b,)?%s@%s\n/

    condition:
        ssh_binary and ($daemon or $client)
}

rule polis_massa {
    meta:
        description = "Rule to detect Polis Massa family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /\b\w+(:|\s-+>)\s%s(:%d)?\s\t(\w+)?:\s%s\s\t(\w+)?:\s%s/

    condition:
        ssh_binary and $log
}

rule quarren {
    meta:
        description = "Rule to detect Quarren family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "h: %s, u: %s, p: %s\n"

    condition:
        ssh_binary and $log
}
// Stantinko yara rules
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2017, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"

rule beds_plugin {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko BEDS' plugins"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.exports("CheckDLLStatus") and
        pe.exports("GetPluginData") and
        pe.exports("InitializePlugin") and
        pe.exports("IsReleased") and
        pe.exports("ReleaseDLL")
}

rule beds_dropper {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "BEDS dropper"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.imphash() == "a7ead4ef90d9981e25728e824a1ba3ef"
        
}

rule facebook_bot {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko's Facebook bot"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "m_upload_pic&return_uri=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
        $s2 = "D:\\work\\brut\\cms\\facebook\\facebookbot\\Release\\facebookbot.pdb" fullword ascii
        $s3 = "https%3A%2F%2Fm.facebook.com%2Fcomment%2Freplies%2F%3Fctoken%3D" fullword ascii
        $s4 = "reg_fb_gate=https%3A%2F%2Fm.facebook.com%2Freg" fullword ascii
        $s5 = "reg_fb_ref=https%3A%2F%2Fm.facebook.com%2Freg%2F" fullword ascii
        $s6 = "&return_uri_error=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii

        $x1 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword ascii
        $x2 = "registration@facebookmail.com" fullword ascii
        $x3 = "https://m.facebook.com/profile.php?mds=" fullword ascii
        $x4 = "https://upload.facebook.com/_mupload_/composer/?profile&domain=" fullword ascii
        $x5 = "http://staticxx.facebook.com/connect/xd_arbiter.php?version=42#cb=ff43b202c" fullword ascii
        $x6 = "https://upload.facebook.com/_mupload_/photo/x/saveunpublished/" fullword ascii
        $x7 = "m.facebook.com&ref=m_upload_pic&waterfall_source=" fullword ascii
        $x8 = "payload.commentID" fullword ascii
        $x9 = "profile.login" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($s*) or 3 of ($x*) ) ) or ( all of them )
}

rule pds_plugins {
 
    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko PDS' plugins"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "std::_Vector_val<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
        $s2 = "std::_Vector_val<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
        $s3 = "std::vector<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
        $s4 = "std::vector<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
        $s5 = "CHTTPHeaderManager" fullword ascii
        $s6 = "CHTTPPostItemManager *" fullword ascii
        $s7 = "CHTTPHeaderManager *" fullword ascii
        $s8 = "CHTTPPostItemManager" fullword ascii
        $s9 = "CHTTPHeader" fullword ascii
        $s10 = "CHTTPPostItem" fullword ascii
        $s11 = "std::vector<CCookie *,std::allocator<CCookie *> >" fullword ascii
        $s12 = "std::_Vector_val<CCookie *,std::allocator<CCookie *> >" fullword ascii
        $s13 = "CCookieManager *" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 2 of ($s*) ) )
}

rule stantinko_pdb {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko malware family PDB path"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "D:\\work\\service\\service\\" ascii

    condition:
        all of them
}

rule stantinko_droppers {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko droppers"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        // Bytes from the encrypted payload
        $s1 = {55 8B EC 83 EC 08 53 56 BE 80 F4 45 00 57 81 EE 80 0E 41 00 56 E8 6D 23 00 00 56 8B D8 68 80 0E 41 00 53 89 5D F8 E8 65 73 00 00 8B 0D FC F5 45}

        // Keys to decrypt payload
        $s2 = {7E 5E 7F 8C 08 46 00 00 AB 57 1A BB 91 5C 00 00 FA CC FD 76 90 3A 00 00}

    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule stantinko_d3d {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko d3dadapter component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.exports("EntryPoint") and
        pe.exports("ServiceMain") and
        pe.imports("WININET.DLL", "HttpAddRequestHeadersA")
}

rule stantinko_ihctrl32 {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko ihctrl32 component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "ihctrl32.dll"
        $s2 = "win32_hlp"
        $s3 = "Ihctrl32Main"
        $s4 = "I%citi%c%size%s%c%ci%s"
        $s5 = "Global\\Intel_hctrl32"

    condition:
        2 of them
}

rule stantinko_wsaudio {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko wsaudio component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        // Export
        $s1 = "GetInterface"
        $s2 = "wsaudio.dll"

        // Event name
        $s3 = "Global\\Wsaudio_Initialize"
        $s4 = "SOFTWARE\\Classes\\%s.FieldListCtrl.1\\"

    condition:
        2 of them
}

rule stantinko_ghstore {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko ghstore component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "G%cost%sSt%c%s%s%ce%sr" wide
        $s2 = "%cho%ct%sS%sa%c%s%crve%c" wide
        $s3 = "Par%c%ce%c%c%s" wide
        $s4 = "S%c%curity%c%s%c%s" wide
        $s5 = "Sys%c%s%c%c%su%c%s%clS%c%s%serv%s%ces" wide

    condition:
        3 of them
}
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2022, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"

rule apt_Windows_TA410_Tendyron_dropper
{
    meta:
        description = "TA410 Tendyron Dropper"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        $s1 = "Global\\{F473B3BE-08EE-4710-A727-9E248F804F4A}" wide
        $s2 = "Global\\8D32CCB321B2" wide
        $s3 = "Global\\E4FE94F75490" wide
        $s4 = "Program Files (x86)\\Internet Explorer\\iexplore.exe" wide
        $s5 = "\\RPC Control\\OLE" wide
        $s6 = "ALPC Port" wide
    condition:
        int16(0) == 0x5A4D and 4 of them
}

rule apt_Windows_TA410_Tendyron_installer
{
    meta:
        description = "TA410 Tendyron Installer"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        $s1 = "Tendyron" wide
        $s2 = "OnKeyToken_KEB.dll" wide
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s4 = "Global\\8D32CCB321B2"
        $s5 = "\\RTFExploit\\"
    condition:
        int16(0) == 0x5A4D and 3 of them
}

rule apt_Windows_TA410_Tendyron_Downloader
{
    meta:
        description = "TA410 Tendyron Downloader"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        /*
        0x401250 8A10                          mov dl, byte ptr [eax]
        0x401252 80F25C                        xor dl, 0x5c
        0x401255 80C25C                        add dl, 0x5c
        0x401258 8810                          mov byte ptr [eax], dl
        0x40125a 40                            inc eax
        0x40125b 83E901                        sub ecx, 1
        0x40125e 75F0                          jne 0x401250
         */
        $chunk_1 = {
            8A 10
            80 F2 5C
            80 C2 5C
            88 10
            40
            83 E9 01
            75 ??
        }
        $s1 = "startModule" fullword
    condition:
        int16(0) == 0x5A4D and all of them
}

rule apt_Windows_TA410_X4_strings
{
    meta:
        description = "Matches various strings found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"
    strings:
        $s1 = "[X]InLoadSC" ascii wide nocase
        $s3 = "MachineKeys\\Log\\rsa.txt" ascii wide nocase
        $s4 = "MachineKeys\\Log\\output.log" ascii wide nocase
    condition:
        any of them
}

rule apt_Windows_TA410_X4_hash_values
{
    meta:
        description = "Matches X4 hash function found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"
    strings:
        $s1 = {D1 10 76 C2 B6 03}
        $s2 = {71 3E A8 0D}
        $s3 = {DC 78 94 0E}
        $s4 = {40 0D E7 D6 06}
        $s5 = {83 BB FD E8 06}
        $s6 = {92 9D 9B FF EC 03}
        $s7 = {DD 0E FC FA F5 03}
        $s8 = {15 60 1E FB F5 03}
    condition:
        uint16(0) == 0x5a4d and 4 of them

}

rule apt_Windows_TA410_X4_hash_fct
{
    meta:
        description = "Matches X4 hash function found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"

    /*
    0x6056cc2150 0FB601                        movzx eax, byte ptr [rcx]
    0x6056cc2153 84C0                          test al, al
    0x6056cc2155 7416                          je 0x6056cc216d
    0x6056cc2157 4869D283000000                imul rdx, rdx, 0x83
    0x6056cc215e 480FBEC0                      movsx rax, al
    0x6056cc2162 4803D0                        add rdx, rax
    0x6056cc2165 48FFC1                        inc rcx
    0x6056cc2168 E9E3FFFFFF                    jmp 0x6056cc2150
     */
    strings:
        $chunk_1 = {
            0F B6 01
            84 C0
            74 ??
            48 69 D2 83 00 00 00
            48 0F BE C0
            48 03 D0
            48 FF C1
            E9 ?? ?? ?? ??
        }

    condition:
        uint16(0) == 0x5a4d and any of them

}

rule apt_Windows_TA410_LookBack_decryption
{
    meta:
        description = "Matches encryption/decryption function used by LookBack."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $initialize = {
            8B C6           //mov eax, esi
            99              //cdq
            83 E2 03        //and edx, 3
            03 C2           //add eax, edx
            C1 F8 02        //sar eax, 2
            8A C8           //mov cl, al
            02 C0           //add al, al
            02 C8           //add cl, al
            88 4C 34 10         //mov byte ptr [esp + esi + 0x10], cl
            46              //inc esi
            81 FE 00 01 00 00       //cmp esi, 0x100
            72 ??
        }
        $generate = {
            8A 94 1C 10 01 ?? ??    //mov dl, byte ptr [esp + ebx + 0x110]
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            0F B6 C3        //movzx eax, bl
            0F B6 44 04 10      //movzx eax, byte ptr [esp + eax + 0x10]
            32 C2           //xor al, dl
            02 F0           //add dh, al
            0F B6 C6        //movzx eax, dh
            03 C8           //add ecx, eax
            0F B6 01        //movzx eax, byte ptr [ecx]
            88 84 1C 10 01 ?? ??    //mov byte ptr [esp + ebx + 0x110], al
            43              //inc ebx
            88 11           //mov byte ptr [ecx], dl
            81 FB 00 06 00 00       //cmp ebx, 0x600
            72 ??           //jb 0x10025930
        }
        $decrypt = {
            0F B6 C6        //movzx eax, dh
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            03 C8           //add ecx, eax
            8A 19           //mov bl, byte ptr [ecx]
            8A C3           //mov al, bl
            02 C6           //add al, dh
            FE C6           //inc dh
            02 F8           //add bh, al
            0F B6 C7        //movzx eax, bh
            8A 94 04 10 01 ?? ??    //mov dl, byte ptr [esp + eax + 0x110]
            88 9C 04 10 01 ?? ??    //mov byte ptr [esp + eax + 0x110], bl
            88 11           //mov byte ptr [ecx], dl
            0F B6 C2        //movzx eax, dl
            0F B6 CB        //movzx ecx, bl
            33 C8           //xor ecx, eax
            8A 84 0C 10 01 ?? ??    //mov al, byte ptr [esp + ecx + 0x110]
            30 04 2E        //xor byte ptr [esi + ebp], al
            46              //inc esi
            3B F7           //cmp esi, edi
            7C ??           //jl 0x10025980
        }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_loader
{
    meta:
        description = "Matches the modified function in LookBack libcurl loader."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $chunk_1 = {
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530e0]
            6A 40          //push 0x40
            68 00 10 00 00     //push 0x1000
            68 F0 04 00 00     //push 0x4f0
            6A 00          //push 0
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530d4]
            8B E8          //mov ebp, eax
            B9 3C 01 00 00     //mov ecx, 0x13c
            BE 60 30 06 10     //mov esi, 0x10063060
            8B FD          //mov edi, ebp
            68 F0 04 00 00     //push 0x4f0
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            55             //push ebp
            E8 ?? ?? ?? ??     //call 0x100258d0
            8B 0D ?? ?? ?? ??      //mov ecx, dword ptr [0x100530e4]
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x100530c8]
            68 6C 02 00 00     //push 0x26c
            89 4C 24 ??        //mov dword ptr [esp + 0x1c], ecx
            89 44 24 ??        //mov dword ptr [esp + 0x20], eax
            FF 15 ?? ?? ?? ??      //call dword ptr [0x10063038]
            8B D8          //mov ebx, eax
            B9 9B 00 00 00     //mov ecx, 0x9b
            BE 50 35 06 10     //mov esi, 0x10063550
            8B FB          //mov edi, ebx
            68 6C 02 00 00      //push 0x26c
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            53             //push ebx
            E8 ?? ?? ?? ??     //call 0x100258d0
            83 C4 14           //add esp, 0x14
            8D 44 24 ??        //lea eax, [esp + 0x10]
            50             //push eax
            53             //push ebx
            8D 44 24 ??        //lea eax, [esp + 0x3c]
            50             //push eax
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x10063058]
            FF 74 24 ??        //push dword ptr [esp + 0x28]
            03 C5          //add eax, ebp
            FF D0          //call eax
        }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_strings
{
    meta:
        description = "Matches multiple strings and export names in TA410 LookBack."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "SodomMainFree" ascii wide
        $s2 = "SodomMainInit" ascii wide
        $s3 = "SodomNormal.bin" ascii wide
        $s4 = "SodomHttp.bin" ascii wide
        $s5 = "sodom.ini" ascii wide
        $s6 = "SodomMainProc" ascii wide

    condition:
        uint16(0) == 0x5a4d and (2 of them or pe.exports("SodomBodyLoad") or pe.exports("SodomBodyLoadTest"))
}

rule apt_Windows_TA410_LookBack_HTTP
{
    meta:
        description = "Matches LookBack's hardcoded HTTP request"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "POST http://%s/status.php?r=%d%d HTTP/1.1\x0d\nAccept: text/html, application/xhtml+xml, */*\x0d\nAccept-Language: en-us\x0d\nUser-Agent: %s\x0d\nContent-Type: application/x-www-form-urlencoded\x0d\nAccept-Encoding: gzip, deflate\x0d\nHost: %s\x0d\nContent-Length: %d\x0d\nConnection: Keep-Alive\x0d\nCache-Control: no-cache\x0d\n\x0d\n" ascii wide
        $s2 = "id=1&op=report&status="

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_magic
{
    meta:
        description = "Matches message header creation in LookBack."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = {
            C7 03 C2 2E AB 48           //mov dword ptr [ebx], 0x48ab2ec2
            ( A1 | 8B 15 ) ?? ?? ?? ??      //mov (eax | edx), x
            [0-1]               //push ebp
            89 ?3 04            //mov dword ptr [ebc + 4], reg
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            89 4? 08            //mov dword ptr [ebx + 8], ??
            89 ?? 0C            //mov dword ptr [ebx + 0xc], ??
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            [1-2]               //push 1 or 2 args
            E8 ?? ?? ?? ??          //call
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_loader_strings
{
    meta:
        description = "Matches various strings found in TA410 FlowCloud first stage."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $key = "y983nfdicu3j2dcn09wur9*^&initialize(y4r3inf;'fdskaf'SKF"
        $s2 = "startModule" fullword
        $s4 = "auto_start_module" wide
        $s5 = "load_main_module_after_install" wide
        $s6 = "terminate_if_fail" wide
        $s7 = "clear_run_mru" wide
        $s8 = "install_to_vista" wide
        $s9 = "load_ext_module" wide
        $s10= "sll_only" wide
        $s11= "fail_if_already_installed" wide
        $s12= "clear_hardware_info" wide
        $s13= "av_check" wide fullword
        $s14= "check_rs" wide
        $s15= "check_360" wide
        $s16= "responsor.dat" wide ascii
        $s17= "auto_start_after_install_check_anti" wide fullword
        $s18= "auto_start_after_install" wide fullword
        $s19= "extern_config.dat" wide fullword
        $s20= "is_hhw" wide fullword
        $s21= "SYSTEM\\Setup\\PrintResponsor" wide
        $event= "Global\\Event_{201a283f-e52b-450e-bf44-7dc436037e56}" wide ascii
        $s23= "invalid encrypto hdr while decrypting"

    condition:
        uint16(0) == 0x5a4d and ($key or $event or 5 of ($s*))
}

rule apt_Windows_TA410_FlowCloud_header_decryption
{
    meta:
        description = "Matches the function used to decrypt resources headers in TA410 FlowCloud"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
    /*
    0x416a70 8B1E              mov ebx, dword ptr [esi]
    0x416a72 8BCF              mov ecx, edi
    0x416a74 D3CB              ror ebx, cl
    0x416a76 8D0C28            lea ecx, [eax + ebp]
    0x416a79 83C706            add edi, 6
    0x416a7c 3018              xor byte ptr [eax], bl
    0x416a7e 8B1E              mov ebx, dword ptr [esi]
    0x416a80 D3CB              ror ebx, cl
    0x416a82 8D0C02            lea ecx, [edx + eax]
    0x416a85 305801            xor byte ptr [eax + 1], bl
    0x416a88 8B1E              mov ebx, dword ptr [esi]
    0x416a8a D3CB              ror ebx, cl
    0x416a8c 8B4C240C              mov ecx, dword ptr [esp + 0xc]
    0x416a90 03C8              add ecx, eax
    0x416a92 305802            xor byte ptr [eax + 2], bl
    0x416a95 8B1E              mov ebx, dword ptr [esi]
    0x416a97 D3CB              ror ebx, cl
    0x416a99 8B4C2410              mov ecx, dword ptr [esp + 0x10]
    0x416a9d 03C8              add ecx, eax
    0x416a9f 305803            xor byte ptr [eax + 3], bl
    0x416aa2 8B1E              mov ebx, dword ptr [esi]
    0x416aa4 D3CB              ror ebx, cl
    0x416aa6 8B4C2414              mov ecx, dword ptr [esp + 0x14]
    0x416aaa 03C8              add ecx, eax
    0x416aac 83C006            add eax, 6
    0x416aaf 3058FE            xor byte ptr [eax - 2], bl
    0x416ab2 8B1E              mov ebx, dword ptr [esi]
    0x416ab4 D3CB              ror ebx, cl
    0x416ab6 3058FF            xor byte ptr [eax - 1], bl
    0x416ab9 83FF10            cmp edi, 0x10
    0x416abc 72B2              jb 0x416a70
     */
    strings:
        $chunk_1 = {
            8B 1E
            8B CF
            D3 CB
            8D 0C 28
            83 C7 06
            30 18
            8B 1E
            D3 CB
            8D 0C 02
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            83 C0 06
            30 58 ??
            8B 1E
            D3 CB
            30 58 ??
            83 FF 10
            72 ??
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_dll_hijacking_strings
{
    meta:
        description = "Matches filenames inside TA410 FlowCloud malicious DLL."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $dat1 = "emedres.dat" wide
        $dat2 = "vviewres.dat" wide
        $dat3 = "setlangloc.dat" wide
        $dll1 = "emedres.dll" wide
        $dll2 = "vviewres.dll" wide
        $dll3 = "setlangloc.dll" wide
    condition:
        uint16(0) == 0x5a4d and (all of ($dat*) or all of ($dll*))
}

rule apt_Windows_TA410_FlowCloud_malicious_dll_antianalysis
{
    meta:
        description = "Matches anti-analysis techniques used in TA410 FlowCloud hijacking DLL."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
    /*
        33C0              xor eax, eax
        E8320C0000            call 0x10001d30
        83C010            add eax, 0x10
        3D00000080            cmp eax, 0x80000000
        7D01              jge +3
        EBFF              jmp +1 / jmp eax
        E050              loopne 0x1000115c / push eax
        C3                ret
    */
        $chunk_1 = {
            33 C0
            E8 ?? ?? ?? ??
            83 C0 10
            3D 00 00 00 80
            7D 01
            EB FF
            E0 50
            C3
        }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_pdb
{
    meta:
        description = "Matches PDB paths found in TA410 FlowCloud."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"

    condition:
        uint16(0) == 0x5a4d and (pe.pdb_path contains "\\FlowCloud\\trunk\\" or pe.pdb_path contains "\\flowcloud\\trunk\\")
}

rule apt_Windows_TA410_FlowCloud_shellcode_decryption
{
    meta:
        description = "Matches the decryption function used in TA410 FlowCloud self-decrypting DLL"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    /*
    0x211 33D2              xor edx, edx
    0x213 8B4510            mov eax, dword ptr [ebp + 0x10]
    0x216 BB6B040000            mov ebx, 0x46b
    0x21b F7F3              div ebx
    0x21d 81C2A8010000          add edx, 0x1a8
    0x223 81E2FF000000          and edx, 0xff
    0x229 8B7D08            mov edi, dword ptr [ebp + 8]
    0x22c 33C9              xor ecx, ecx
    0x22e EB07              jmp 0x237
    0x230 301439            xor byte ptr [ecx + edi], dl
    0x233 001439            add byte ptr [ecx + edi], dl
    0x236 41                inc ecx
    0x237 3B4D0C            cmp ecx, dword ptr [ebp + 0xc]
    0x23a 72F4              jb 0x230
     */
    strings:
        $chunk_1 = {
            33 D2
            8B 45 ??
            BB 6B 04 00 00
            F7 F3
            81 C2 A8 01 00 00
            81 E2 FF 00 00 00
            8B 7D ??
            33 C9
            EB ??
            30 14 39
            00 14 39
            41
            3B 4D ??
            72 ??
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_fcClient_strings
{
    meta:
        description = "Strings found in fcClient/rescure.dat module."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "df257bdd-847c-490e-9ef9-1d7dc883d3c0"
        $s2 = "\\{2AFF264E-B722-4359-8E0F-947B85594A9A}"
        $s3 = "Global\\{26C96B51-2B5D-4D7B-BED1-3DCA4848EDD1}" wide
        $s4 = "{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" wide
        $s5 = "{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" wide
        $s6 = "XXXModule_func.dll"
        $driver1 = "\\drivers\\hidmouse.sys" wide fullword
        $driver2 = "\\drivers\\hidusb.sys" wide fullword

    condition:
        uint16(0) == 0x5a4d and (any of ($s*) or all of ($driver*))
}

rule apt_Windows_TA410_FlowCloud_fcClientDll_strings
{
    meta:
        description = "Strings found in fcClientDll/responsor.dat module."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "http://%s/html/portlet/ext/draco/resources/draco_manager.swf/[[DYNAMIC]]/1"
        $s2 = "Cookie: COOKIE_SUPPORT=true; JSESSIONID=5C7E7A60D01D2891F40648DAB6CB3DF4.jvm1; COMPANY_ID=10301; ID=666e7375545678695645673d; PASSWORD=7a4b48574d746470447a303d; LOGIN=6863303130; SCREEN_NAME=4a2b455377766b657451493d; GUEST_LANGUAGE_ID=en-US"
        $fc_msg = ".fc_net.msg"
        $s4 = "\\pipe\\namedpipe_keymousespy_english" wide
        $s5 = "8932910381748^&*^$58876$%^ghjfgsa413901280dfjslajflsdka&*(^7867=89^&*F(^&*5678f5ds765f76%&*%&*5"
        $s6 = "cls_{CACB140B-0B82-4340-9B05-7983017BA3A4}" wide
        $s7 = "HTTP/1.1 200 OK\x0d\nServer: Apache-Coyote/1.1\x0d\nPragma: No-cache\x0d\nCache-Control: no-cache\x0d\nExpires: Thu, 01 Jan 1970 08:00:00 CST\x0d\nLast-Modified: Fri, 27 Apr 2012 08:11:04 GMT\x0d\nContent-Type: application/xml\x0d\nContent-Length: %d\x0d\nDate: %s GMT"
        $sql1 = "create table if not exists table_filed_space"
        $sql2 = "create table if not exists clipboard"
        $sql3 = "create trigger if not exists file_after_delete after delete on file"
        $sql4 = "create trigger if not exists file_data_after_insert after insert on file_data"
        $sql5 = "create trigger if not exists file_data_after_delete after delete on file_data"
        $sql6 = "create trigger if not exists file_data_after_update after update on file_data"
        $sql7 = "insert into file_data(file_id, ofs, data, status)"

    condition:
        uint16(0) == 0x5a4d and (any of ($s*) or #fc_msg >= 8 or 4 of ($sql*))
}

rule apt_Windows_TA410_Rootkit_strings
{
    meta:
        description = "Strings found in TA410's Rootkit"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $driver1 = "\\Driver\\kbdclass" wide
        $driver2 = "\\Driver\\mouclass" wide
        $device1 = "\\Device\\KeyboardClass0" wide
        $device2 = "\\Device\\PointerClass0" wide
        $driver3 = "\\Driver\\tcpip" wide
        $device3 = "\\Device\\tcp" wide
        $driver4 = "\\Driver\\nsiproxy" wide
        $device4 = "\\Device\\Nsi" wide
        $reg1 = "\\Registry\\Machine\\SYSTEM\\Setup\\AllowStart\\ceipCommon" wide
        $reg2 = "RHH%d" wide
        $reg3 = "RHP%d" wide
        $s1 = "\\SystemRoot\\System32\\drivers\\hidmouse.sys" wide

    condition:
        uint16(0) == 0x5a4d and all of ($s1,$reg*) and (all of ($driver*) or all of ($device*))
}

rule apt_Windows_TA410_FlowCloud_v5_resources
{
    meta:
        description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 5.0.2"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    condition:
        uint16(0) == 0x5a4d and pe.number_of_resources >= 13 and
        for 12 resource in pe.resources:
        ( resource.type == 10 and resource.language == 1033 and
            //resource name is one of 100, 1000, 10000, 1001, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 2000, 2001 as widestring
            (resource.name_string == "1\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x000\x00" or
             resource.name_string == "1\x000\x000\x001\x00" or resource.name_string == "1\x000\x001\x00" or resource.name_string == "1\x000\x002\x00" or
             resource.name_string == "1\x000\x003\x00" or resource.name_string == "1\x000\x004\x00" or resource.name_string == "1\x000\x005\x00" or
             resource.name_string == "1\x000\x006\x00" or resource.name_string == "1\x000\x007\x00" or resource.name_string == "1\x000\x008\x00" or
             resource.name_string == "1\x000\x009\x00" or resource.name_string == "1\x001\x000\x00" or resource.name_string == "2\x000\x000\x000\x00" or resource.name_string == "2\x000\x000\x001\x00")
        )
}

rule apt_Windows_TA410_FlowCloud_v4_resources
{
    meta:
        description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 4.1.3"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    condition:
        uint16(0) == 0x5a4d and pe.number_of_resources >= 6 and
        for 5 resource in pe.resources:
        ( resource.type == 10 and resource.language == 1033 and
            // resource name is one of 10000, 10001, 10002, 10003, 10004, 10005, 10100 as wide string
            (resource.name_string == "1\x000\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x001\x00" or
             resource.name_string == "1\x000\x000\x000\x002\x00" or resource.name_string == "1\x000\x000\x000\x003\x00" or
             resource.name_string == "1\x000\x000\x000\x004\x00" or resource.name_string == "1\x000\x000\x000\x005\x00" or resource.name_string == "1\x000\x001\x000\x000\x00")
        )
}
// Operation Windigo yara rules
// For feedback or questions contact us at: windigo@eset.sk
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2014, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
rule onimiki
{
  meta:
    description = "Linux/Onimiki malicious DNS server"
    malware = "Linux/Onimiki"
    operation = "Windigo"
    author = "Olivier Bilodeau <bilodeau@eset.com>"
    created = "2014-02-06"
    reference = "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
    contact = "windigo@eset.sk"
    source = "https://github.com/eset/malware-ioc/"
    license = "BSD 2-Clause"

  strings:
    // code from offset: 0x46CBCD
    $a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}
    $a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}
    $a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}
    $a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}
    $a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}
    $a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}
    $a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}
    $a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}
    $a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}

  condition:
    all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"
		hash =  "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		8B [2]   mov     eax, [ebp+var_C]
		89 ??    mov     ecx, eax
		03 [2]   add     ecx, [ebp+lpBuffer]
		8B [2]   mov     eax, [ebp+var_C]
		03 [2]   add     eax, [ebp+lpBuffer]
		0F B6 18 movzx   ebx, byte ptr [eax]
		8B [2]   mov     eax, [ebp+var_C]
		89 ??    mov     edx, eax
		C1 [2]   sar     edx, 1Fh
		C1 [2]   shr     edx, 1Eh
		01 ??    add     eax, edx
		83 [2]   and     eax, 3
		29 ??    sub     eax, edx
		03 [2]   add     eax, [ebp+arg_8]
		0F B6 00 movzx   eax, byte ptr [eax]
		31 ??    xor     eax, ebx
		88 ??    mov     [ecx], al
	*/

	$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }
	
	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash =  "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+var_20]
		8A [2]          mov     al, [edi+edx]
		30 [2]          xor     [ebx+ecx], al
	*/

	$decoderFunc  = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash =  "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
  // Decoder function for the embedded payload
	$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"
		hash =  "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+arg_8]
		8A [2]          mov     al, [edi+edx]
		30 ??           xor     [ebx], al
		8A ??           mov     al, [ebx]
		4?              inc     ebx
		88 [2]          mov     [esi+ecx], al
	*/

	$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }
	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		hash =  "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+28h], 5Ch ; '\'
		C7 [3] 65 00 00 00  mov     dword ptr [esp+24h], 65h ; 'e'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+20h], 70h ; 'p'
		C7 [3] 69 00 00 00  mov     dword ptr [esp+1Ch], 69h ; 'i'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+18h], 70h ; 'p'
		F7 F1               div     ecx
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+14h], 5Ch ; '\'
		C7 [3] 2E 00 00 00  mov     dword ptr [esp+10h], 2Eh ; '.'
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+0Ch], 5Ch ; '\'
	*/

	$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
  $fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash =  "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		8B [2]      mov     eax, [rbp+var_4]
		48 98       cdqe
		48 89 C1    mov     rcx, rax
		48 03 4D 10 add     rcx, [rbp+arg_0]
		8B 45 FC    mov     eax, [rbp+var_4]
		48 98       cdqe
		48 03 45 10 add     rax, [rbp+arg_0]
		44 0F B6 00 movzx   r8d, byte ptr [rax]
		8B 45 FC    mov     eax, [rbp+var_4]
		89 C2       mov     edx, eax
		C1 FA 1F    sar     edx, 1Fh
		C1 EA 1E    shr     edx, 1Eh
		01 D0       add     eax, edx
		83 E0 03    and     eax, 3
		29 D0       sub     eax, edx
		48 98       cdqe
		48 03 45 20 add     rax, [rbp+arg_10]
		0F B6 00    movzx   eax, byte ptr [rax]
		44 31 C0    xor     eax, r8d
		88 01       mov     [rcx], al
	*/

	$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }
		
	condition:
		$a
}

rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash =  "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 C0                xor     eax, eax
		EB 0F                jmp     short loc_6BAC16B5
		41 83 E1 03          and     r9d, 3
		47 8A 0C 08          mov     r9b, [r8+r9]
		44 30 0C 01          xor     [rcx+rax], r9b
		48 FF C0             inc     rax
		39 D0                cmp     eax, edx
		41 89 C1             mov     r9d, eax
		7C EA                jl      short loc_6BAC16A6
		4C 8D 05 53 29 00 00 lea     r8, aRundll32Exe; "rundll32.exe"
		E9 D1 FE FF FF       jmp     sub_6BAC1599
	*/

	$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}

rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash =  "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		41 B8 5C 00 00 00       mov     r8d, 5Ch ; '\'
		C7 44 24 50 5C 00 00 00 mov     [rsp+68h+var_18], 5Ch ; '\'
		C7 44 24 48 65 00 00 00 mov     [rsp+68h+var_20], 65h ; 'e'
		C7 44 24 40 70 00 00 00 mov     [rsp+68h+var_28], 70h ; 'p'
		C7 44 24 38 69 00 00 00 mov     [rsp+68h+var_30], 69h ; 'i'
		C7 44 24 30 70 00 00 00 mov     [rsp+68h+var_38], 70h ; 'p'
		C7 44 24 28 5C 00 00 00 mov     dword ptr [rsp+68h+lpThreadId], 5Ch ; '\'
		C7 44 24 20 2E 00 00 00 mov     [rsp+68h+dwCreationFlags], 2Eh ; '.'
		89 54 24 58             mov     [rsp+68h+var_10], edx
		48 8D 15 22 38 00 00    lea     rdx, Format; Format
		E8 0D 17 00 00          call    sprintf
	*/

	$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}

  $fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Beacon_Dll_v1_44
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.44"
    hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 5 cases
      53        push    ebx
      8B D9     mov     ebx, ecx; a2
      83 FA 04  cmp     edx, 4
      77 36     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10018F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10001AD4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }    
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_45
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.45"
    hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      51        push    ecx
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 9 cases
      53        push    ebx
      56        push    esi
      83 FA 08  cmp     edx, 8
      77 6B     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10019F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10002664
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_46
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.46"
    hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      8B F2             mov     esi, edx
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 8E 00 00 00 ja      def_1000107F; jumptable 1000107F default case, case 8
      FF 24 ??          jmp     ds:jpt_1000107F[ecx*4]; switch jump
    */   
    $version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001D040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_10002A04
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_47
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.47"
    hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 F8 12  cmp     eax, 12h
      77 10     ja      short def_100010BB; jumptable 100010BB default case, case 8
      FF 24 ??  jmp     ds:jpt_100010BB[eax*4]; switch jump
    */
    $version_sig = { 83 F8 12 77 10 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001E040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_48
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.48"
    hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48        dec     eax; switch 24 cases
      57        push    edi
      8B F1     mov     esi, ecx
      8B DA     mov     ebx, edx
      83 F8 17  cmp     eax, 17h
      77 12     ja      short def_1000115D; jumptable 1000115D default case, case 8
      FF 24 ??  jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001F048[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_100047B4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.49"
    hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                   dec     eax; switch 31 cases
      56                   push    esi
      83 F8 1E             cmp     eax, 1Eh
      0F 87 23 01 00 00    ja      def_1000115B; jumptable 1000115B default case, cases 8,30
      FF 24 85 80 12 00 10 jmp     ds:jpt_1000115B[eax*4]; switch jump
    */
    $version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
    
    /*
      B1 69            mov     cl, 69h ; 'i'
      90               nop
      30 88 [4]        xor     byte ptr word_10022038[eax], cl
      40               inc     eax
      3D A8 01 00 00   cmp     eax, 1A8h
      7C F2            jl      short loc_10005940
    */    
    $decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }
      
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_0_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
    hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 F8 22          cmp     eax, 22h
      0F 87 96 01 00 00 ja      def_1000115D; jumptable 1000115D default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }

    /*
      B1 69            mov     cl, 69h ; 'i'
      EB 03            jmp     short loc_10006930
      8D 49 00         lea     ecx, [ecx+0]
      30 88 [4]        xor     byte ptr word_10023038[eax], cl
      40               inc     eax
      3D 30 05 00 00   cmp     eax, 530h
      72 F2            jb      short loc_10006930
    */
    $decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2
{
  // v2.1 and v2.2 use the exact same beacon binary (matching hashes)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
    hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      49                dec     ecx; switch 37 cases
      56                push    esi
      57                push    edi
      83 F9 24          cmp     ecx, 24h
      0F 87 8A 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
    hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      49                dec     ecx; switch 39 cases
      56                push    esi
      57                push    edi
      83 F9 26          cmp     ecx, 26h
      0F 87 A9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
    hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      4A                dec     edx; switch 48 cases
      56                push    esi
      57                push    edi
      83 FA 2F          cmp     edx, 2Fh
      0F 87 F9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112E[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_5
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
    hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 59 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3A          cmp     eax, 3Ah
      0F 87 6E 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_0
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
    hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 61 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3C          cmp     eax, 3Ch
      0F 87 89 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_1
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.1"
    hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // v3.1 and v3.2 share the same C2 handler code. We are using a function that
  // is not included in v3.2 to mark the v3.1 version along with the decoder
  // which allows us to narrow in on only v3.1 samples
  strings:
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_2
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
    hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
    rs2 ="a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 62 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3D          cmp     eax, 3Dh
      0F 87 83 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

    // Since v3.1 and v3.2 are so similiar, we use the v3.1 version_sig
    // as a negating condition to diff between 3.1 and 3.2
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

  condition:
    $version_sig and $decoder and not $version3_1_sig
}

rule CobaltStrike_Resources_Beacon_Dll_v3_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
    hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 66 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 41          cmp     eax, 41h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
    hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 67 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 42          cmp     eax, 42h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1
{
  // Version 3.5-hf1 and 3.5.1 use the exact same beacon binary (same hash)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
    hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 68 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 43          cmp     eax, 43h
      0F 87 07 03 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_6
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
    hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 72 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 47          cmp     eax, 47h
      0F 87 2F 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_7
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
    hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 74 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 49          cmp     eax, 49h
      0F 87 47 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */   
    $version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_8
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
    hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 76 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 4B          cmp     eax, 4Bh
      0F 87 5D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

    // XMRig uses a v3.8 sample to trick sandboxes into running their code. 
    // These samples are the same and useless. This string removes many
    // of them from our detection
    $xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
    // To remove others, we look for known xmrig C2 domains in the config:
    $c2_1 = "ns7.softline.top" xor
    $c2_2 = "ns8.softline.top" xor
    $c2_3 = "ns9.softline.top" xor
    //$a = /[A-Za-z]{1020}.{4}$/
    
  condition:
    $version_sig and $decoder and (2 of ($c2_*) or $xmrig_srcpath)
}

/*

  missing specific signatures for 3.9 and 3.10 since we don't have samples

*/

rule CobaltStrike_Resources_Beacon_Dll_v3_11
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
    hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // Original version from April 9, 2018
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 11 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
    hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
    rs2 ="4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  // Covers both 3.11 (bug fix form May 25, 2018) and v3.12
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 0D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_13
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
    hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      4A                dec     edx; switch 91 cases
      56                push    esi
      57                push    edi
      83 FA 5A          cmp     edx, 5Ah
      0F 87 2D 03 00 00 ja      def_10008D01; jumptable 10008D01 default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??          jmp     ds:jpt_10008D01[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_14
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
    hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
    rs2 ="87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 FA 5B  cmp     edx, 5Bh
      77 15     ja      short def_1000939E; jumptable 1000939E default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??  jmp     ds:jpt_1000939E[edx*4]; switch jump
    */
    $version_sig = { 83 FA 5B 77 15 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      51                   push    ecx
      4A                   dec     edx; switch 99 cases
      56                   push    esi
      57                   push    edi
      83 FA 62             cmp     edx, 62h
      0F 87 8F 03 00 00    ja      def_100077C3; jumptable 100077C3 default case, cases 2,6-8,20,21,25,26,30,34-36,63-66
      FF 24 95 56 7B 00 10 jmp     ds:jpt_100077C3[edx*4]; switch jump
    */

    $version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }

    /*
      80 B0 20 00 03 10 ??  xor     byte_10030020[eax], 2Eh
      40                    inc     eax
      3D 00 10 00 00        cmp     eax, 1000h
      7C F1                 jl      short loc_1000912B
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
    hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
    rs2 ="9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 100 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 63          cmp     eax, 63h
      0F 87 3C 03 00 00 ja      def_10007F28; jumptable 10007F28 default case, cases 2,6-8,20,21,25,26,29,30,34-36,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007F28[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
    hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
    rs2 ="78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 102 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 65          cmp     eax, 65h
      0F 87 47 03 00 00 ja      def_10007EAD; jumptable 10007EAD default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007EAD[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
    hash =  "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:

    /*
      53                push    ebx
      56                push    esi
      48                dec     eax; switch 104 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 67          cmp     eax, 67h
      0F 87 5E 03 00 00 ja      def_10008997; jumptable 10008997 default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
    */
    $version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }

    /*
      80 B0 [5]      xor     byte_10033020[eax], 2Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_1000ADA1
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

/*

 64-bit Beacons.
 
 These signatures are a bit different. The decoders are all identical in the 4.x
 series and the command processor doesn't use a switch/case idiom, but rather
 an expanded set of if/then/else branches. This invalidates our method for
 detecting the versions of the beacons by looking at the case count check
 used by the 32-bit versions. As such, we are locking in on "random",
 non-overlapping between version, sections of code in the command processor. 
 While a reasonable method is to look for blocks of Jcc which will have specific
 address offsets per version, this generally is insufficient due to the lack of 
 code changes. As such, the best method appears to be to look for specific
 function call offsets

 NOTE: There are only VERY subtle differences between the following versions:
  * 3.2 and 3.3
  * 3.4 and 3.5-hf1/3.5.1
  * 3.12, 3.13 and 3.14
  * 4.3 and 4.4-4.6 . 
  
 Be very careful if you modify the $version_sig field for either of those rules. 
*/


rule CobaltStrike_Resources_Beacon_x64_v3_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
    hash =  "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      4C 8D 05 9F F8 FF FF lea     r8, sub_18000C4B0
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 05 1A 00 00       call    sub_18000E620
      EB 0A                jmp     short loc_18000CC27
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 41 21 00 00       call    sub_18000ED68
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
    
    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
    hash =  "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 89 66 00 00       call    sub_1800155E8
      E9 23 FB FF FF       jmp     loc_18000EA87
      41 B8 01 00 00 00    mov     r8d, 1
      E9 F3 FD FF FF       jmp     loc_18000ED62
      48 8D 0D 2A F8 FF FF lea     rcx, sub_18000E7A0
      E8 8D 2B 00 00       call    sub_180011B08
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_4
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
    hash =  "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 56 6F 00 00    call    sub_180014458
      E9 17 FB FF FF    jmp     loc_18000D01E
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 41 4D 00 00    call    sub_180012258
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
    */
    $version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001600E
    */
    
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
    hash =  "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 38 70 00 00    call    sub_180014548
      E9 FD FA FF FF    jmp     loc_18000D012
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 3F 4D 00 00    call    sub_180012264
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
      5F                pop     rdi
    */

    $version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 
                     48 8B 5C 24 30 48 83 C4 20 5F }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
    hash =  "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 27          cmp     ecx, 27h ; '''
      0F 87 47 03 00 00 ja      loc_18000D110
      0F 84 30 03 00 00 jz      loc_18000D0FF
      83 F9 14          cmp     ecx, 14h
      0F 87 A4 01 00 00 ja      loc_18000CF7C
      0F 84 7A 01 00 00 jz      loc_18000CF58
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 C8 00 00 00 ja      loc_18000CEAF
      0F 84 B3 00 00 00 jz      loc_18000CEA0
    */
    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_7
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
    hash =  "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 28          cmp     ecx, 28h ; '('
      0F 87 7F 03 00 00 ja      loc_18000D148
      0F 84 67 03 00 00 jz      loc_18000D136
      83 F9 15          cmp     ecx, 15h
      0F 87 DB 01 00 00 ja      loc_18000CFB3
      0F 84 BF 01 00 00 jz      loc_18000CF9D
    */

    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016ECA
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_8
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
    hash =  "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 7A 52 00 00 call    sub_18001269C
      EB 0D          jmp     short loc_18000D431
      45 33 C0       xor     r8d, r8d
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi; Src
      E8 8F 55 00 00 call    sub_1800129C0
    */

    $version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001772E
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_11
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
    hash =  "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
    rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
	
    /*
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 2D          cmp     ecx, 2Dh ; '-'
      0F 87 B2 03 00 00 ja      loc_18000D1EF
      0F 84 90 03 00 00 jz      loc_18000D1D3
      83 F9 17          cmp     ecx, 17h
      0F 87 F8 01 00 00 ja      loc_18000D044
      0F 84 DC 01 00 00 jz      loc_18000D02E
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 F9 00 00 00 ja      loc_18000CF54
      0F 84 DD 00 00 00 jz      loc_18000CF3E
      FF C9             dec     ecx
      0F 84 C0 00 00 00 jz      loc_18000CF29
      83 E9 02          sub     ecx, 2
      0F 84 A6 00 00 00 jz      loc_18000CF18
      FF C9             dec     ecx
    */

    $version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180017DCA
    */

    $decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_12
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
    hash =  "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 F8 2E 00 00 call    sub_180010384
      EB 16          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 00 5C 00 00 call    f_OTH__Command_75
      EB 0A          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 64 4F 00 00 call    f_OTH__Command_74
    */
    $version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018205
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Resources_Beacon_x64_v3_13
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
    hash =  "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 8D 0D 01 5B FF FF lea     rcx, f_NET__ExfiltrateData
      48 83 C4 28          add     rsp, 28h
      E9 A8 54 FF FF       jmp     f_OTH__Command_85
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; lpSrc
      E8 22 55 FF FF       call    f_OTH__Command_84
    */

    $version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
      
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018C01
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_14
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
    hash =  "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
    rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:

    /*
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Src
      48 83 C4 28    add     rsp, 28h
      E9 B1 1F 00 00 jmp     f_OTH__Command_69
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Source
      48 83 C4 28    add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800196BD
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      41 B8 01 00 00 00    mov     r8d, 1
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 D1 B3 FF FF       jmp     sub_180010C5C
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 AF F5 FF FF       jmp     f_UNK__Command_92__ChangeFlag
      45 33 C0             xor     r8d, r8d
      4C 8D 0D 8D 70 FF FF lea     r9, sub_18000C930
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      E8 9B B0 FF FF       call    f_OTH__Command_91__WrapInjection
    */

    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
    hash =  "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      83 F9 34          cmp     ecx, 34h ; '4'
      0F 87 8E 03 00 00 ja      loc_180016259
      0F 84 7A 03 00 00 jz      loc_18001624B
      83 F9 1C          cmp     ecx, 1Ch
      0F 87 E6 01 00 00 ja      loc_1800160C0
      0F 84 D7 01 00 00 jz      loc_1800160B7
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 E9 00 00 00 ja      loc_180015FD2
      0F 84 CE 00 00 00 jz      loc_180015FBD
      FF C9             dec     ecx
      0F 84 B8 00 00 00 jz      loc_180015FAF
      83 E9 02          sub     ecx, 2
      0F 84 9F 00 00 00 jz      loc_180015F9F
      FF C9             dec     ecx
    */

    $version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }


    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
    hash =  "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
  
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 D3 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 84 6E FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
  
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800186E1
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
    hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 83 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 A4 6D FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }

    /*
      80 34 28 2E       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800184D9
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
    hash =  "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      41 B8 01 00 00 00 mov     r8d, 1
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      48 83 C4 28       add     rsp, 28h
      E9 E8 AB FF FF    jmp     sub_1800115A4
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      E8 1A EB FF FF    call    f_UNK__Command_92__ChangeFlag
      48 83 C4 28       add     rsp, 28h
    */
    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018E1F
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bind64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"
		hash =  "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for reverse64 and bind really differ slightly, here we are using the inclusion of additional calls
  // found in bind64 to differentate between this and reverse64
  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,
  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be
  // unchanged. This means we can use these values as anchors in our signature.
	/*
		41 BA C2 DB 37 67 mov     r10d, bind
		FF D5             call    rbp
		48 31 D2          xor     rdx, rdx
		48 89 F9          mov     rcx, rdi
		41 BA B7 E9 38 FF mov     r10d, listen
		FF D5             call    rbp
		4D 31 C0          xor     r8, r8
		48 31 D2          xor     rdx, rdx
		48 89 F9          mov     rcx, rdi
		41 BA 74 EC 3B E1 mov     r10d, accept
		FF D5             call    rbp
		48 89 F9          mov     rcx, rdi
		48 89 C7          mov     rdi, rax
		41 BA 75 6E 4D 61 mov     r10d, closesocket
	*/

	$calls = {
			41 BA C2 DB 37 67
			FF D5
			48 [2]
			48 [2]
			41 BA B7 E9 38 FF
			FF D5
			4D [2]
			48 [2]
			48 [2]
			41 BA 74 EC 3B E1
			FF D5
			48 [2]
			48 [2]
			41 BA 75 6E 4D 61
		}
		
	condition:
		$apiLocator and $calls
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash =  "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for bind.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}

  // bind.bin, unlike reverse.bin, listens for incoming connections. Using the API hashes for listen and accept is a solid
  // approach to finding bind.bin specific samples
	/*
		5?             push    ebx
		5?             push    edi
		68 B7 E9 38 FF push    listen
		FF ??          call    ebp
		5?             push    ebx
		5?             push    ebx
		5?             push    edi
		68 74 EC 3B E1 push    accept
	*/
	$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}
	
	condition:
		$apiLocator and $ws2_32 and $listenaccept
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule  CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		hash =  "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		FF [1-5]        call    ds:recv               // earlier versions (v1.x to 2.x) this is CALL EBP
		83 ?? FF        cmp     eax, 0FFFFFFFFh
		74 ??           jz      short loc_100020D5
		85 C0           test    eax, eax
		(74  | 76) ??   jz      short loc_100020D5    // earlier versions (v1.x to 2.x) used jbe (76) here
		03 ??           add     esi, eax
		83 ?? 02        cmp     esi, 2
		72 ??           jb      short loc_100020D1
		80 ?? 3E FF 0A  cmp     byte ptr [esi+edi-1], 0Ah
		75 ??           jnz     short loc_100020D1
		80 ?? 3E FE 0D  cmp     byte ptr [esi+edi-2], 0Dh
	*/

	$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		
  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"
		hash =  "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		FF 15 [4]         call    cs:recv
		83 ?? FF          cmp     eax, 0FFFFFFFFh
		74 ??             jz      short loc_1800018FB
		85 ??             test    eax, eax
		74 ??             jz      short loc_1800018FB
		03 ??             add     ebx, eax
		83 ?? 02          cmp     ebx, 2
		72 ??             jb      short loc_1800018F7
		8D ?? FF          lea     eax, [rbx-1]
		80 [2] 0A         cmp     byte ptr [rax+rdi], 0Ah
		75 ??             jnz     short loc_1800018F7
		8D ?? FE          lea     eax, [rbx-2]
		80 [2] 0D         cmp     byte ptr [rax+rdi], 0Dh
	*/

	$socket_recv = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}

  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"
		
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"
		hash =  "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		5?                 push    eax; ReturnLength
		5?                 push    edi; TokenInformationLength
		5?                 push    edi; TokenInformation
		8B ??              mov     ebx, ecx
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		75 ??              jnz     short loc_10001100
		FF 15 [4]          call    ds:GetLastError
		83 ?? 7A           cmp     eax, 7Ah ; 'z'
		75 ??              jnz     short loc_10001100
		FF [2]             push    [ebp+ReturnLength]; uBytes
		5?                 push    edi; uFlags
		FF 15 [4]          call    ds:LocalAlloc
		8B ??              mov     esi, eax
		8D [2]             lea     eax, [ebp+ReturnLength]
		5?                 push    eax; ReturnLength
		FF [2]             push    [ebp+ReturnLength]; TokenInformationLength
		5?                 push    esi; TokenInformation
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		74 ??              jz      short loc_10001103
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthorityCount
		8A ??              mov     al, [eax]
		FE C8              dec     al
		0F B6 C0           movzx   eax, al
		5?                 push    eax; nSubAuthority
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthority
		B? 01 00 00 00     mov     ecx, 1
		5?                 push    esi; hMem
		81 ?? 00 30 00 00  cmp     dword ptr [eax], 3000h
	*/

	$isHighIntegrityProcess = {
			5? 
			5? 
			5? 
			8B ?? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			75 ?? 
			FF 15 [4]
			83 ?? 7A 
			75 ?? 
			FF [2]
			5? 
			FF 15 [4]
			8B ?? 
			8D [2]
			5? 
			FF [2]
			5? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			74 ?? 
			FF ?? 
			FF 15 [4]
			8A ?? 
			FE C8
			0F B6 C0
			5? 
			FF ?? 
			FF 15 [4]
			B? 01 00 00 00 
			5? 
			81 ?? 00 30 00 00 
		}

	/*
		6A 3C               push    3Ch ; '<'; Size
		8D ?? C4            lea     eax, [ebp+pExecInfo]
		8B ??               mov     edi, edx
		6A 00               push    0; Val
		5?                  push    eax; void *
		8B ??               mov     esi, ecx
		E8 [4]              call    _memset
		83 C4 0C            add     esp, 0Ch
		C7 [2] 3C 00 00 00  mov     [ebp+pExecInfo.cbSize], 3Ch ; '<'
		8D [2]              lea     eax, [ebp+pExecInfo]
		C7 [2] 40 00 00 00  mov     [ebp+pExecInfo.fMask], 40h ; '@'
		C7 [6]              mov     [ebp+pExecInfo.lpFile], offset aTaskmgrExe; "taskmgr.exe"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpParameters], 0
		5?                  push    eax; pExecInfo
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpDirectory], 0
		C7 [6]              mov     [ebp+pExecInfo.lpVerb], offset aRunas; "runas"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.nShow], 0
		FF 15 [4]           call    ds:ShellExecuteExW
		FF 75 FC            push    [ebp+pExecInfo.hProcess]; Process
	*/

	$executeTaskmgr = {
			6A 3C
			8D ?? C4 
			8B ?? 
			6A 00
			5? 
			8B ?? 
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00 
			8D [2]
			C7 [2] 40 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			5? 
			C7 [2] 00 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			FF 15 [4]
			FF 75 FC
		}
		
	condition:
		all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"
		hash =  "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		83 F8 7A          cmp     eax, 7Ah ; 'z'
		75 59             jnz     short loc_1800014BC
		8B 54 24 48       mov     edx, dword ptr [rsp+38h+uBytes]; uBytes
		33 C9             xor     ecx, ecx; uFlags
		FF 15 49 9C 00 00 call    cs:LocalAlloc
		44 8B 4C 24 48    mov     r9d, dword ptr [rsp+38h+uBytes]; TokenInformationLength
		8D 53 19          lea     edx, [rbx+19h]; TokenInformationClass
		48 8B F8          mov     rdi, rax
		48 8D 44 24 48    lea     rax, [rsp+38h+uBytes]
		48 8B CE          mov     rcx, rsi; TokenHandle
		4C 8B C7          mov     r8, rdi; TokenInformation
		48 89 44 24 20    mov     [rsp+38h+ReturnLength], rax; ReturnLength
		FF 15 B0 9B 00 00 call    cs:GetTokenInformation
		85 C0             test    eax, eax
		74 2D             jz      short loc_1800014C1
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 AB 9B 00 00 call    cs:GetSidSubAuthorityCount
		8D 73 01          lea     esi, [rbx+1]
		8A 08             mov     cl, [rax]
		40 2A CE          sub     cl, sil
		0F B6 D1          movzx   edx, cl; nSubAuthority
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 9F 9B 00 00 call    cs:GetSidSubAuthority
		81 38 00 30 00 00 cmp     dword ptr [rax], 3000h
	*/

	$isHighIntegrityProcess = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}

	/*
		44 8D 42 70             lea     r8d, [rdx+70h]; Size
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; void *
		E8 2E 07 00 00          call    memset
		83 64 24 50 00          and     [rsp+98h+pExecInfo.nShow], 0
		48 8D 05 E2 9B 00 00    lea     rax, aTaskmgrExe; "taskmgr.exe"
		0F 57 C0                xorps   xmm0, xmm0
		66 0F 7F 44 24 40       movdqa  xmmword ptr [rsp+98h+pExecInfo.lpParameters], xmm0
		48 89 44 24 38          mov     [rsp+98h+pExecInfo.lpFile], rax
		48 8D 05 E5 9B 00 00    lea     rax, aRunas; "runas"
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; pExecInfo
		C7 44 24 20 70 00 00 00 mov     [rsp+98h+pExecInfo.cbSize], 70h ; 'p'
		C7 44 24 24 40 00 00 00 mov     [rsp+98h+pExecInfo.fMask], 40h ; '@'
		48 89 44 24 30          mov     [rsp+98h+pExecInfo.lpVerb], rax
		FF 15 05 9B 00 00       call    cs:ShellExecuteExW
	*/

	$executeTaskmgr = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15 
		}


	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		hash =  "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		8B ??     mov     ecx, [eax]
		5?        push    edx
		5?        push    eax
		FF ?? 48  call    dword ptr [ecx+48h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001177
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}

	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		FF ?? 08  push    [ebp+copyName]
		8B ??     mov     ecx, [eax]
		FF [5]    push    dstFile
		FF [5]    push    srcFile
		5?        push    eax
		FF ?? 40  call    dword ptr [ecx+40h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001026  // this line can also be 0F 85 <32-bit offset>
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		
				
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash =  "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 8B 0D 07 A4 01 00 mov     rcx, cs:fileop
		45 33 C0             xor     r8d, r8d
		48 8B 01             mov     rax, [rcx]
		FF 90 90 00 00 00    call    qword ptr [rax+90h]
		85 C0                test    eax, eax
		75 D9                jnz     short loc_180001022
		48 8B 0D F0 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
		85 C0                test    eax, eax
	*/

	$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}	
	
	
	/*
		48 8B 0D 32 A3 01 00 mov     rcx, cs:fileop
		4C 8B 05 3B A3 01 00 mov     r8, cs:dstFile
		48 8B 15 2C A3 01 00 mov     rdx, cs:srcFile
		48 8B 01             mov     rax, [rcx]
		4C 8B CD             mov     r9, rbp
		48 89 5C 24 20       mov     [rsp+38h+var_18], rbx
		FF 90 80 00 00 00    call    qword ptr [rax+80h]
		85 C0                test    eax, eax
		0F 85 7B FF FF FF    jnz     loc_1800010B0
		48 8B 0D 04 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
	*/

	$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		hash =  "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:		
    // the command.ps1 and compress.ps1 are the same file. Between v3.7 and v3.8 the file was renamed from command to compress.
    $ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
    $ps2 ="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase
  
  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		hash =  "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		5?                  push    esi
		68 [4]              push    offset ProcName; "IsWow64Process"
		68 [4]              push    offset ModuleName; "kernel32"
		C7 [3-5] 00 00 00 00  mov     [ebp+var_9C], 0                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		FF 15 [4]           call    ds:GetModuleHandleA
		50                  push    eax; hModule
		FF 15 [4]           call    ds:GetProcAddress
		8B ??               mov     esi, eax
		85 ??               test    esi, esi
		74 ??               jz      short loc_1000298B
		8D [3-5]            lea     eax, [ebp+var_9C]                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		5?                  push    eax
		FF 15 [4]           call    ds:GetCurrentProcess
		50                  push    eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
		}

	/*
		6A 00          push    0; AccessMode
		5?             push    esi; FileName
		E8 [4]         call    __access
		83 C4 08       add     esp, 8
		83 F8 FF       cmp     eax, 0FFFFFFFFh
		74 ??          jz      short loc_100028A7
		5?             push    esi
		68 [4]         push    offset aWarningSExists; "Warning: %s exists\n"   // this may not exist in v2.x samples
		E8 [4]         call    nullsub_1
		83 C4 08       add     esp, 8             // if the push doesnt exist, then this is 04, not 08
		// v2.x has a PUSH ESI here... so we need to skip that
		6A 00          push    0; hTemplateFile
		68 80 01 00 00 push    180h; dwFlagsAndAttributes
		6A 02          push    2; dwCreationDisposition
		6A 00          push    0; lpSecurityAttributes
		6A 05          push    5; dwShareMode
		68 00 00 00 40 push    40000000h; dwDesiredAccess
		5?             push    esi; lpFileName
		FF 15 [4]      call    ds:CreateFileA
		8B ??          mov     edi, eax
		83 ?? FF       cmp     edi, 0FFFFFFFFh
		75 ??          jnz     short loc_100028E2
		FF 15 [4]      call    ds:GetLastError
		5?             push    eax
	*/

	$dropFile = {
			6A 00
			5? 
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ?? 
			5? 
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5? 
			FF 15 [4]
			8B ?? 
			83 ?? FF 
			75 ?? 
			FF 15 [4]
			5? 
		}
	
	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		hash =  "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		C7 04 24 [4]    mov     dword ptr [esp], offset aKernel32; "kernel32"
		E8 [4]          call    GetModuleHandleA
		83 EC 04        sub     esp, 4
		C7 44 24 04 [4] mov     dword ptr [esp+4], offset aIswow64process; "IsWow64Process"
		89 04 24        mov     [esp], eax; hModule
		E8 59 14 00 00  call    GetProcAddress
		83 EC 08        sub     esp, 8
		89 45 ??        mov     [ebp+var_C], eax
		83 7D ?? 00     cmp     [ebp+var_C], 0
		74 ??           jz      short loc_4019BA
		E8 [4]          call    GetCurrentProcess
		8D [2]          lea     edx, [ebp+fIs64bit]
		89 [3]          mov     [esp+4], edx
		89 04 24        mov     [esp], eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}

	/*
		C7 44 24 04 00 00 00 00 mov     dword ptr [esp+4], 0; AccessMode
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24                mov     [esp], eax; FileName
		E8 [4]                  call    _access
		83 F8 FF                cmp     eax, 0FFFFFFFFh
		74 ??                   jz      short loc_40176D
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24 04             mov     [esp+4], eax
		C7 04 24 [4]            mov     dword ptr [esp], offset aWarningSExists; "Warning: %s exists\n"
		E8 [4]                  call    log
		E9 [4]                  jmp     locret_401871
		C7 44 24 18 00 00 00 00 mov     dword ptr [esp+18h], 0; hTemplateFile
		C7 44 24 14 80 01 00 00 mov     dword ptr [esp+14h], 180h; dwFlagsAndAttributes
		C7 44 24 10 02 00 00 00 mov     dword ptr [esp+10h], 2; dwCreationDisposition
		C7 44 24 0C 00 00 00 00 mov     dword ptr [esp+0Ch], 0; lpSecurityAttributes
		C7 44 24 08 05 00 00 00 mov     dword ptr [esp+8], 5; dwShareMode
		C7 44 24 04 00 00 00 40 mov     dword ptr [esp+4], 40000000h; dwDesiredAccess
		8B [2]                  mov     eax, [ebp+FileName]
		89 04 24                mov     [esp], eax; lpFileName
		E8 [4]                  call    CreateFileA
		83 EC 1C                sub     esp, 1Ch
		89 45 ??                mov     [ebp+hFile], eax
	*/

	$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}

	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase
			
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Dnsstager_Bin_v1_47_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"
		hash =  "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for dnsstager.bin specific bytes helps delineate sample types
	  $dnsapi = { 68 64 6E 73 61 }	
	
	condition:
		$apiLocator and $dnsapi
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash =  "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		6A 00               push    0; lParam
		6A 28               push    28h ; '('; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		C7 [5] 01 00 00 00  mov     dword_10017E70, 1
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 27               push    27h ; '''; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 00               push    0; wParam
		68 01 02 00 00      push    201h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
	*/

	$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}

		
	condition:
		$wnd_proc
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash =  "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		81 FA 21 01 00 00             cmp     edx, 121h
		75 4A                         jnz     short loc_1800017A9
		83 3D 5A 7E 01 00 00          cmp     cs:dword_1800195C0, 0
		75 41                         jnz     short loc_1800017A9
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		C7 05 48 7E 01 00 01 00 00 00 mov     cs:dword_1800195C0, 1
		45 8D 41 28                   lea     r8d, [r9+28h]; wParam
		FF 15 36 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		45 8D 41 27                   lea     r8d, [r9+27h]; wParam
		48 8B CB                      mov     rcx, rbx; hWnd
		FF 15 23 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		45 33 C0                      xor     r8d, r8d; wParam
		BA 01 02 00 00                mov     edx, 201h; Msg
		48 8B CB                      mov     rcx, rbx; hWnd
	*/

	$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}

	condition:
		$wnd_proc
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpsstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		hash =  "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		BA 1F 00 00 00    mov     edx, 1Fh
		6A 00             push    0
		68 80 33 00 00    push    3380h
		49 89 E0          mov     r8, rsp
		41 B9 04 00 00 00 mov     r9d, 4
		41 BA 75 46 9E 86 mov     r10d, InternetSetOptionA
	*/

	$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}	
	
	condition:
		$apiLocator and $InternetSetOptionA
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		hash =  "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		6A 04          push    4
		5?             push    eax
		6A 1F          push    1Fh
		5?             push    esi
		68 75 46 9E 86 push    InternetSetOptionA
		FF ??          call    ebp
	*/

	$InternetSetOptionA = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}
	
	condition:
		$apiLocator and $InternetSetOptionA
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		hash =  "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really the inclusion or exclusion of InternetSetOptionA. However,
  // there is a subtle difference in the jmp after the InternetOpenA call (short jmp for x86 and long jmp for x64)
	/*
		41 BA 3A 56 79 A7 mov     r10d, InternetOpenA
		FF D5             call    rbp
		EB 61             jmp     short j_get_c2_ip
	*/

	$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}

	
	condition:
		$apiLocator and $postInternetOpenJmp
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		hash =  "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API
  // and the httpstager controls the download loop slightly different than the httpsstager
	/*
		B? 00 2F 00 00  mov     edi, 2F00h
		39 ??           cmp     edi, eax
		74 ??           jz      short loc_100000E9
		31 ??           xor     edi, edi
		E9 [4]          jmp     loc_100002CA      // opcode could also be EB for a short jump (v2.5-v3.10)
	*/

	$downloaderLoop = {
			B? 00 2F 00 00 
			39 ?? 
			74 ?? 
			31 ?? 
			( E9 | EB )
		}

	condition:
		$apiLocator and $downloaderLoop
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"
		hash =  "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for reverse64 and bind really differ slightly, here we are using the lack of additional calls
  // found in reverse64 to differentate between this and bind64
  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,
  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be
  // unchanged. This means we can use these values as anchors in our signature.
	/*
		41 BA EA 0F DF E0 mov     r10d, WSASocketA
		FF D5             call    rbp
		48 89 C7          mov     rdi, rax
		6A 10             push    10h
		41 58             pop     r8
		4C 89 E2          mov     rdx, r12
		48 89 F9          mov     rcx, rdi
		41 BA 99 A5 74 61 mov     r10d, connect
		FF D5             call    rbp
	*/

	$calls = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}
	condition:
		$apiLocator and $calls
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"
		hash =  "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for reverse.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}


  // reverse.bin makes outbound connection (using connect) while bind.bin listens for incoming connections (using listen)
  // so the presence of the connect API hash is a solid method for distinguishing between the two.
	/*
		6A 10          push    10h
		[0]5?          push    esi
		5?             push    edi
		68 99 A5 74 61 push    connect
	*/
	$connect = {
			6A 10
			5? 
			5? 
			68 99 A5 74 61
		}
	
	condition:
		$apiLocator and $ws2_32 and $connect
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"
		hash =  "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for smbstager.bin specific bytes helps delineate sample types
	  $smb = { 68 C6 96 87 52 }	
	  
	  // This code block helps differentiate between smbstager.bin and metasploit's engine which has reasonable level of overlap
	  	/*
		6A 40          push    40h ; '@'
		68 00 10 00 00 push    1000h
		68 FF FF 07 00 push    7FFFFh
		6A 00          push    0
		68 58 A4 53 E5 push    VirtualAlloc
	*/

	$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}
	
	condition:
		$apiLocator and $smb and $smbstart
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash =  "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:   
    $arch = "platform.architecture()"
    $nope = "WindowsPE"
    $alloc = "ctypes.windll.kernel32.VirtualAlloc"
    $movemem = "ctypes.windll.kernel32.RtlMoveMemory"
    $thread = "ctypes.windll.kernel32.CreateThread"
    $wait = "ctypes.windll.kernel32.WaitForSingleObject"

  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
    $scriptletstart = "<scriptlet>" nocase
    $registration = "<registration progid=" nocase
    $classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
    $scriptend = "</script>" nocase
	  $antiregistration = "</registration>" nocase
    $scriptletend = "</scriptlet>"

  condition:
    all of them and @scriptletstart[1] < @registration[1] and @registration[1] < @classid[1] and @classid[1] < @scriptlang[1] and @scriptlang[1] < @cdata[1]
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash =  "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  $ea = "Excel.Application" nocase
    $vis = "Visible = False" nocase
    $wsc = "Wscript.Shell" nocase
    $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
    $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
    $regwrite = ".RegWrite" nocase
    $dw = "REG_DWORD"
    $code = ".CodeModule.AddFromString"
	 /* Hex encoded Auto_*/ /*Open */
    $ao = { 41 75 74 6f 5f 4f 70 65 6e }
    $da = ".DisplayAlerts"

  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
    $dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
    $imm = "InMemoryModule" nocase
    $mdt = "MyDelegateType" nocase
    $rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
    $data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
    $64bitSpecific = "[IntPtr]::size -eq 8"
    $mandatory = "Mandatory = $True"
    
  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
    $createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
    $allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
    $writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
    $runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
    $vars = "Dim rwxpage As Long" nocase
    $res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
    $rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

  condition:
    all of them and @vars[1] < @res[1] and @allocstuff[1] < @rwxpage[1]
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
    $compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
    $params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
    $paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
    $paramsGIM = ".GenerateInMemory = $True" nocase
    $result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase
    //$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase

    //$64bitSpecific = "[IntPtr]::size -eq 8"
    
    
  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"
		hash =  "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */
    $stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
    $stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}

  condition:
    any of them
}


/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"
		hash =  "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor64.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */

    $stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
    $stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
    $stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}
  
  condition:
    any of them
}
 /*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
   
  strings:
    /*
      C6 45 F0 48 mov     [ebp+var_10], 48h ; 'H'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 61 mov     [ebp+var_E], 61h ; 'a'
      C6 45 F3 70 mov     [ebp+var_D], 70h ; 'p'
      C6 45 F4 41 mov     [ebp+var_C], 41h ; 'A'
      C6 45 F5 6C mov     [ebp+var_B], 6Ch ; 'l'
      C6 45 F6 6C mov     [ebp+var_A], 6Ch ; 'l'
      C6 45 F7 6F mov     [ebp+var_9], 6Fh ; 'o'
      C6 45 F8 63 mov     [ebp+var_8], 63h ; 'c'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9B 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 EC 4D mov     [ebp+var_14], 4Dh ; 'M'
      C6 45 ED 61 mov     [ebp+var_13], 61h ; 'a'
      C6 45 EE 70 mov     [ebp+var_12], 70h ; 'p'
      C6 45 EF 56 mov     [ebp+var_11], 56h ; 'V'
      C6 45 F0 69 mov     [ebp+var_10], 69h ; 'i'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 77 mov     [ebp+var_E], 77h ; 'w'
      C6 45 F3 4F mov     [ebp+var_D], 4Fh ; 'O'
      C6 45 F4 66 mov     [ebp+var_C], 66h ; 'f'
      C6 45 F5 46 mov     [ebp+var_B], 46h ; 'F'
      C6 45 F6 69 mov     [ebp+var_A], 69h ; 'i'
      C6 45 F7 6C mov     [ebp+var_9], 6Ch ; 'l'
      C6 45 F8 65 mov     [ebp+var_8], 65h ; 'e'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9C 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    $core_sig and not $deobfuscator
}


// 64-bit BeaconLoaders

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 38 48 mov     [rsp+78h+var_40], 48h ; 'H'
      C6 44 24 39 65 mov     [rsp+78h+var_3F], 65h ; 'e'
      C6 44 24 3A 61 mov     [rsp+78h+var_3E], 61h ; 'a'
      C6 44 24 3B 70 mov     [rsp+78h+var_3D], 70h ; 'p'
      C6 44 24 3C 41 mov     [rsp+78h+var_3C], 41h ; 'A'
      C6 44 24 3D 6C mov     [rsp+78h+var_3B], 6Ch ; 'l'
      C6 44 24 3E 6C mov     [rsp+78h+var_3A], 6Ch ; 'l'
      C6 44 24 3F 6F mov     [rsp+78h+var_39], 6Fh ; 'o'
      C6 44 24 40 63 mov     [rsp+78h+var_38], 63h ; 'c'
      C6 44 24 41 00 mov     [rsp+78h+var_37], 0
    */

    $core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D1 56 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 58 4D mov     [rsp+98h+var_40], 4Dh ; 'M'
      C6 44 24 59 61 mov     [rsp+98h+var_3F], 61h ; 'a'
      C6 44 24 5A 70 mov     [rsp+98h+var_3E], 70h ; 'p'
      C6 44 24 5B 56 mov     [rsp+98h+var_3D], 56h ; 'V'
      C6 44 24 5C 69 mov     [rsp+98h+var_3C], 69h ; 'i'
      C6 44 24 5D 65 mov     [rsp+98h+var_3B], 65h ; 'e'
      C6 44 24 5E 77 mov     [rsp+98h+var_3A], 77h ; 'w'
      C6 44 24 5F 4F mov     [rsp+98h+var_39], 4Fh ; 'O'
      C6 44 24 60 66 mov     [rsp+98h+var_38], 66h ; 'f'
      C6 44 24 61 46 mov     [rsp+98h+var_37], 46h ; 'F'
      C6 44 24 62 69 mov     [rsp+98h+var_36], 69h ; 'i'
      C6 44 24 63 6C mov     [rsp+98h+var_35], 6Ch ; 'l'
      C6 44 24 64 65 mov     [rsp+98h+var_34], 65h ; 'e'
    */

    $core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D2 57 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 48 56 mov     [rsp+88h+var_40], 56h ; 'V'
      C6 44 24 49 69 mov     [rsp+88h+var_40+1], 69h ; 'i'
      C6 44 24 4A 72 mov     [rsp+88h+var_40+2], 72h ; 'r'
      C6 44 24 4B 74 mov     [rsp+88h+var_40+3], 74h ; 't'
      C6 44 24 4C 75 mov     [rsp+88h+var_40+4], 75h ; 'u'
      C6 44 24 4D 61 mov     [rsp+88h+var_40+5], 61h ; 'a'
      C6 44 24 4E 6C mov     [rsp+88h+var_40+6], 6Ch ; 'l'
      C6 44 24 4F 41 mov     [rsp+88h+var_40+7], 41h ; 'A'
      C6 44 24 50 6C mov     [rsp+88h+var_40+8], 6Ch ; 'l'
      C6 44 24 51 6C mov     [rsp+88h+var_40+9], 6Ch ; 'l'
      C6 44 24 52 6F mov     [rsp+88h+var_40+0Ah], 6Fh ; 'o'
      C6 44 24 53 63 mov     [rsp+88h+var_40+0Bh], 63h ; 'c'
      C6 44 24 54 00 mov     [rsp+88h+var_40+0Ch], 0
    */

    $core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }


    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      33 C0                      xor     eax, eax
      83 F8 01                   cmp     eax, 1
      74 63                      jz      short loc_378
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      0F B7 00                   movzx   eax, word ptr [rax]
      3D 4D 5A 00 00             cmp     eax, 5A4Dh
      75 45                      jnz     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 63 40 3C                movsxd  rax, dword ptr [rax+3Ch]
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 83 7C 24 28 40          cmp     [rsp+38h+var_10], 40h ; '@'
      72 2F                      jb      short loc_369
      48 81 7C 24 28 00 04 00 00 cmp     [rsp+38h+var_10], 400h
      73 24                      jnb     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 8B 4C 24 28             mov     rcx, [rsp+38h+var_10]
      48 03 C8                   add     rcx, rax
      48 8B C1                   mov     rax, rcx
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 8B 44 24 28             mov     rax, [rsp+38h+var_10]
      81 38 50 45 00 00          cmp     dword ptr [rax], 4550h
      75 02                      jnz     short loc_369
    */

    $core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }

    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    $core_sig and not $deobfuscator
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule Sliver_Implant_32bit
{
  meta:
    description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    hash =  "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      81 ?? 74 63 70 70     cmp     dword ptr [ecx], 70706374h
      .
      .
      .
      81 ?? 04 69 76 6F 74  cmp     dword ptr [ecx+4], 746F7669h
    */
    $s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }

    // case "wg":
    /*
      66 81 ?? 77 67 cmp     word ptr [eax], 6777h      // "gw"
    */
    $s_wg = { 66 81 ?? 77 67 }

    // case "dns":
    /*
      66 81 ?? 64 6E cmp     word ptr [eax], 6E64h    // "nd"
      .
      .
      .
      80 ?? 02 73    cmp     byte ptr [eax+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "http":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [eax], 70747468h     // "ptth"
     */
    $s_http = { 81 ?? 68 74 74 70 }

    // case "https":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [ecx], 70747468h     // "ptth"
      .
      .
      .
      80 ?? 04 73        cmp     byte ptr [ecx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }

    // case "mtls":       NOTE: this one can be missing due to compilate time config
    /*
      81 ?? 6D 74 6C 73  cmp     dword ptr [eax], 736C746Dh     // "sltm"
    */
    $s_mtls = { 81 ?? 6D 74 6C 73 }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    4 of ($s*) and not 1 of ($fp*)
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule Sliver_Implant_64bit
{
  meta:
    description = "Sliver 64-bit implant (with and without --debug flag at compile)"
    hash =  "2d1c9de42942a16c88a042f307f0ace215cdc67241432e1152080870fe95ea87"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      48 ?? 74 63 70 70 69 76 6F 74 mov     rcx, 746F766970706374h
    */
    $s_tcppivot = { 48 ?? 74 63 70 70 69 76 6F 74 }


    // case "namedpipe":
    /*
      48 ?? 6E 61 6D 65 64 70 69 70 mov     rsi, 70697064656D616Eh      // "pipdeman"
      .
      .
      .
      80 ?? 08 65 cmp     byte ptr [rdx+8], 65h ; 'e'

    */
    $s_namedpipe = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }

    // case "https":
    /*
      81 3A 68 74 74 70 cmp     dword ptr [rdx], 70747468h          // "ptth"
      .
      .
      .
      80 7A 04 73       cmp     byte ptr [rdx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }

    // case "wg":
    /*
      66 81 3A 77 67 cmp     word ptr [rdx], 6777h      // "gw"
    */
    $s_wg = {66 81 ?? 77 67}


    // case "dns":
    /*
      66 81 3A 64 6E cmp     word ptr [rdx], 6E64h     // "nd"
      .
      .
      .
      80 7A 02 73    cmp     byte ptr [rdx+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "mtls":         // This one may or may not be in the file, depending on the config flags.
    /*
       81 ?? 6D 74 6C 73 cmp   dword ptr [rdx], 736C746Dh          // "mtls"
    */
    $s_mtls = {  81 ?? 6D 74 6C 73  }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    5 of ($s*) and not 1 of ($fp*)
}
