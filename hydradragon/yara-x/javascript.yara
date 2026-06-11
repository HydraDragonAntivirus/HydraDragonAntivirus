
/* 
    YARA Rules by Florian
    Mostly based on MSTICs report 
    https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/
    Not shared publicly: rules for CobaltStrike loader samples, ISOs, specifc msiexec method found in some samples
    only available in THOR and VALHALLA
*/

rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_1 {
   meta:
      description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29"
   strings:
      $x1 = "[i].charCodeAt(0) ^ 2);}"
   condition:
      filesize < 5000KB and 1 of them
}

rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_2 {
   meta:
      description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29"
   strings:
      $s1 = "saveAs(blob, " ascii
      $s2 = ".iso\");" ascii
      $s3 = "application/x-cd-image" ascii
      $s4 = ".indexOf(\"Win\")!=-1" ascii
   condition:
      filesize < 5000KB and all of them
}

rule apt_CN_Tetris_JS_simple
{

	meta:
		author      = "@imp0rtp3"
		description = "Jetriz, Swid & Jeniva from Tetris framework signature"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		
	strings:
		$a1 = "c2lnbmFs" // 'noRefererJsonp'
		$a2 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a3 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a4 = "ZmV0Y2g=" // 'return new F('
		$a5 = "c3BsaWNl" // 'Mb2345Browser'
		$a6 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a7 = "Zm9udA==" // 'heartBeats'
		$a8 = "OS4w" // 'addIEMeta'
		$a9 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "UHJlc3Rv" // 'baiduboxapp'
		$a12 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a13 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a14 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a15 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'

		$b1 = "var a0_0x"

	condition:
		$b1 at 0 or
		5 of ($a*)

}

rule APT_EvilNum_JS_Jul_2021_1 {
   meta:
        description = "Detect JS script used by EvilNum group"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2020-07-13"
        hash1 = "8420577149bef1eb12387be3ea7c33f70272e457891dfe08fdb015ba7cd92c72"
        hash2 = "c16824a585c9a77332fc16357b5e00fc110c00535480e9495c627f656bb60f24"
        hash3 = "1061baf604aaa7ed5ba3026b9367de7b6c7f20e7e706d9e9b5308c45a64b2679"
        tlp = "white"
        adversary = "EvilNum"
   strings:
        $s1 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 42 61 73 65 36 34 44 61 74 61 22 29 3b }
        $s2 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 42 61 73 65 36 34 44 61 74 61 22 29 3b }
        $s3 = { 69 66 20 28 2d 31 20 21 3d 20 57 53 63 72 69 70 74 2e 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 2e 69 6e 64 65 78 4f 66 28 [1-8] 28 22 }
        $s4 = { 52 75 6e 28 [1-8] 30 2c 20 30 29 }
        $s5 = { 7d 2c 20 ?? 20 3d 20 ?? 2e 63 68 61 72 43 6f 64 65 41 74 28 30 29 2c 20 ?? 20 3d 20 ?? 2e 73 6c 69 63 65 28 31 2c 20 31 20 2b 20 ?? 29 2c 20 ?? 20 3d 20 ?? 2e 73 6c 69 63 65 28 31 20 2b 20 ?? 20 2b 20 34 29 2c 20 ?? 20 3d 20 5b 5d 2c } 
        $s6 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 3b }
        $s7 = { 5b ?? 5d 20 3d 20 ?? 20 2b 20 22 2d 22 20 2b 20 ?? 20 2b 20 22 2d 22 20 2b 20 ?? 20 2b 20 22 54 22 20 2b 20 ?? 20 2b 20 22 3a 22 20 2b 20 ?? 20 2b 20 22 3a 22 20 2b 20 ?? 3b }
   condition:
        filesize > 8KB and 6 of ($s*)
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-06-26
   Identifier: RANCOR
   Reference: https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_RANCOR_JS_Malware {
   meta:
      description = "Rancor Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "1dc5966572e94afc2fbcf8e93e3382eef4e4d7b5bc02f24069c403a28fa6a458"
   strings:
      $x1 = ",0,0 >%SystemRoot%\\system32\\spool\\drivers\\color\\fb.vbs\",0,0" fullword ascii
      $x2 = "CreateObject(\"Wscript.Shell\").Run \"explorer.exe \"\"http" ascii
      $x3 = "CreateObject(\"Wscript.Shell\").Run \"schtasks /create" ascii
   condition:
      uint16(0) == 0x533c and filesize < 1KB and 1 of them
}


rule MAL_Emotet_JS_Dropper_Oct19_1 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }
   condition:
      uint32(0) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}


rule crime_JS_Chromelogger
{
	meta:
		author      = "@imp0rtp3"
		description = "Chromelogger Add-on YARA"
		reference   = "https://github.com/vxunderground/MalwareSourceCode/blob/main/Javascript/Trojan.Javascript.ChromeLogger.a.zip"

	strings:
		$a1 = "spyjs_saveData"
		$a2 = "spyjs_getInput"
		$a3 = "').unbind('change')"
		$a4 = "log1.php?values="
		$a5 = "spyjs_refreshEvents"
		$a6 = "http://127.0.0.1/server/"

	condition:
		4 of ($*)
}rule MAL_ZIP_SocGholish_Mar21_1 : zip js socgholish {
    meta:
        description = "Triggers on small zip files with typical SocGholish JS files in it"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        hash = "4f6566c145be5046b6be6a43c64d0acae38cada5eb49b2f73135b3ac3d6ba770"
        hash = "54f756fbf8c20c76af7c9f538ff861690800c622d1c9db26eb3afedc50835b09"
        hash = "dfdbec1846b74238ba3cfb8c7580c64a0fa8b14b6ed2b0e0e951cc6a9202dd8d"
    strings:
        $a1 = /\.[a-z0-9]{6}\.js/ ascii
        $a2 = "Chrome" ascii
        $a3 = "Opera" ascii

        $b1 = "Firefox.js" ascii
        $b2 = "Edge.js" ascii
    condition:
        uint16(0) == 0x4b50 and filesize > 1300 and filesize < 1600 and (
            2 of ($a*) or
            any of ($b*)
        )
}

rule MAL_JS_SocGholish_Mar21_1 : js socgholish {
    meta:
        description = "Triggers on SocGholish JS files"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
        hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
        hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
    strings:
        $try = "try" ascii

        $s1 = "new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s2 = "['DeleteFile']" ascii
        $s3 = "['WScript']['ScriptFullName']" ascii
        $s4 = "['WScript']['Sleep'](1000)" ascii
        $s5 = "new ActiveXObject('MSXML2.XMLHTTP')" ascii
        $s6 = "this['eval']" ascii
        $s7 = "String['fromCharCode']"
        $s8 = "2), 16)," ascii
        $s9 = "= 103," ascii
        $s10 = "'00000000'" ascii
    condition:
        $try in (0 .. 10) and filesize > 3KB and filesize < 5KB and 8 of ($s*)
}

rule SocGholish_JS_Inject_1
{
	meta:
		author = "Josh Trombley "
		date_created = "9/2/2021"

	strings:
		$s0 = "cmVmZXJyZXI="
		$s1 = "Oi8vKFteL10rKS8="
		$s2 = "dXNlckFnZW50"
		$s3 = "bG9jYWxTdG9yYWdl"
		$s4 = "V2luZG93cw=="
		$s5 = "aHJlZg=="
		$s6 = "QW5kcm9pZA=="

	condition:
		4 of them		
}

rule SocGholish_JS_Inject_2
{
	meta:
		author = "Josh Trombley "
		date_created = "9/2/2021"

	strings:
		$s0 = "new RegExp("
		$s1 = "document.createElement('script')"
		$s2 = "type = 'text/javascript'"
		$s3 = "document.getElementsByTagName('script')"
		$s4 = ".parentNode.insertBefore("
    	$s5 = "=window.atob("
    	$s6 = ".async=trye;"

	condition:
		all of them		
}

/*
   YARA Rule Set
   Author: Florian Roth
   Date: 2018-09-18
   Identifier: Xbash
   License: https://creativecommons.org/licenses/by-nc/4.0/
   Reference: https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/
*/

/* Rule Set ----------------------------------------------------------------- */


rule MAL_Xbash_JS_Sep18 {
   meta:
      description = "Detects XBash malware"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18"
      hash1 = "f888dda9ca1876eba12ffb55a7a993bd1f5a622a30045a675da4955ede3e4cb8"
   strings:
      $s1 = "var path=WSHShell" fullword ascii
      $s2 = "var myObject= new ActiveXObject(" fullword ascii
      $s3 = "window.resizeTo(0,0)" fullword ascii
      $s4 = "<script language=\"JScript\">" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x483c and filesize < 5KB and
      8 of them
}
/*

   Generic Cloaking

   Florian Roth
   Nextron Systems GmbH

	License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/



rule Obfuscated_JS_April17 {
   meta:
      description = "Detects cloaked Mimikatz in JS obfuscation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21"
   strings:
      $s1 = "\";function Main(){for(var "  ascii
      $s2 = "=String.fromCharCode(parseInt(" ascii
      $s3 = "));(new Function(" ascii
   condition:
      filesize < 500KB and all of them
}

rule Malware_JS_powershell_obfuscated {
   meta:
      description = "Unspecified malware - file rechnung_3.js"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-24"
      hash1 = "3af15a2d60f946e0c4338c84bd39880652f676dc884057a96a10d7f802215760"
   strings:
      $x1 = "po\" + \"wer\" + \"sh\" + \"e\" + \"ll\";" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}

/* Various rules - see the references */

rule JS_Suspicious_Obfuscation_Dropbox {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
      $x2 = "script:https://www.dropbox.com" ascii
   condition:
      2 of them
}

rule JS_Suspicious_MSHTA_Bypass {
   meta:
      description = "Detects MSHTA Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition:
      2 of them
}

rule JavaScript_Run_Suspicious {
   meta:
      description = "Detects a suspicious Javascript Run command"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      score = 60
      date = "2017-08-23"
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition:
      all of them
}


rule Suspicious_JS_script_content {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Research on Leviathan https://goo.gl/MZ7dRg"
      date = "2017-12-02"
      score = 70
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition:
      ( filesize < 10KB and 1 of them )
}

rule Universal_Exploit_Strings {
   meta:
      description = "Detects a group of strings often used in exploit codes"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "not set"
      date = "2017-12-02"
      score = 50
      hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"
   strings:
      $s1 = "Exploit" fullword ascii
      $s2 = "Payload" fullword ascii
      $s3 = "CVE-201" ascii
      $s4 = "bindshell"
   condition:
      ( filesize < 2KB and 3 of them )
}


rule Loa_JS_Gootkit_Nov_2020_1 {
   meta:
      description = "Detect JS loader used on the Gootkit killchain (November 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ffforward/status/1330214661577437187"
      date = "2020-11-21"
      hash1 = "7aec3ed791529182c0f64ce34415c3c705a79f3d628cbcff70c34a9f73d8ff42"
   strings:
      $s1 = { 7b [4-6] 5b [4-6] 5d 28 [4-6] 5b [4-6] 5d 29 28 [4-6] 5b [4-6] 5d 29 3b 7d } // Exec method -> {F[F](F[F])(F[F]);}
      $s2 = { 7b 72 65 74 75 72 6e 20 [4-6] 20 25 20 28 [4-6] 2b [4-6] 29 3b 7d } // Modulo OP -> {return F % (F+F);} 
      $s3 = { 7b [4-6] 20 3d 20 [4-6] 28 [4-6] 29 2e 73 70 6c 69 74 28 [4-6] 29 3b 7d } // Split OP -> {F = F(F).split(F);}
      $s4 = { 7b 72 65 74 75 72 6e 20 [4-6] 2e 63 68 61 72 41 74 28 [4-6] 29 3b 7d} // Getchar OP -> {return F.charAt(F);} 
      $s5 = { 7b [4-6] 5b [4-6] 5d 20 3d 20 [4-6] 5b [4-6] 5b [4-6] 5d 5d 3b 7d }  // GetIndex OP -> {F[F] = F[F[F]];} 
   condition:
      filesize > 1KB and 2 of them 
}
rule meow_js_miner
{

    meta:
       author = "Brian Laskowski"
       info = " meow.js cryptominer 05/17/18 "
       license = "GNU GPLv3"
       license_reference = "https://choosealicense.com/licenses/gpl-3.0/"

    strings:
    
   	$s1="data"
	$s7="application/octet-stream"
	$s8="base64"
	$s2="hashsolved"  
	$s3="k.identifier" 
	$s4="acceptedhashes"
	$s5="eth-pocket"
	$s6="8585"

    condition:
    7 of them
}

rule SUSP_JSframework_capstone
{
	meta:
		author      = "@imp0rtp3"
		description = "Detects use of the capstone.js framework (can be used for exploit, not necessarily malicious)"
		reference   = "https://alexaltea.github.io/capstone.js/"
		refenrce_2  = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"


	strings:
		$a1 = "_cs_insn_name"
		$a2 = "Module = MCapstone"
		$a3 = "var MCapstone"
		$a4 = "Wrapper made by Alexandro Sanchez Bach."
		$a5 = "MCapstone.ccall"
		$a6 = "MCapstone.Pointer_stringify"
		$a7 = "Capstone.js: Function cs_option failed"
		$a8 = "ARM64_SYSREG_ID_ISAR5_EL1"

	condition:
		filesize > 1MB and
		filesize<10MB and
		4 of them

}rule SUSP_JSframework_fingerprint2
{
	meta:
		author      = "@imp0rtp3"
		description = "fingerprint2 JS library signature, can be used for legitimate purposes"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:

		$m1 = "valentin.vasilyev"
		$m2 = "Valentin Vasilyev"
		$m3 = "Fingerprintjs2"
		$a1 = "2277735313"
		$a2 = "289559509"
		$a3 = "1291169091"
		$a4 = "658871167"
		$a5 = "excludeIOS11"
		$a6 = "sortPluginsFor"
		$a7 = "Cwm fjordbank glyphs vext quiz, \\ud83d\\ude03"
		$a8 = "varyinTexCoordinate"
		$a9 = "webgl alpha bits:"
		$a10 = "WEBKIT_EXT_texture_filter_anisotropic"
		$a11 = "mmmmmmmmmmlli"
		$a12 = "'new Fingerprint()' is deprecated, see https://github.com/Valve/fingerprintjs2#upgrade-guide-from-182-to-200"
		$b1 = "AcroPDF.PDF"
		$b2 = "Adodb.Stream"
		$b3 = "AgControl.AgControl"
		$b4 = "DevalVRXCtrl.DevalVRXCtrl.1"
		$b5 = "MacromediaFlashPaper.MacromediaFlashPaper"
		$b6 = "Msxml2.DOMDocument"
		$b7 = "Msxml2.XMLHTTP"
		$b8 = "PDF.PdfCtrl"
		$b9 = "QuickTime.QuickTime"
		$b10 = "QuickTimeCheckObject.QuickTimeCheck.1"
		$b11 = "RealPlayer"
		$b12 = "RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)"
		$b13 = "RealVideo.RealVideo(tm) ActiveX Control (32-bit)"
		$b14 = "Scripting.Dictionary"
		$b15 = "SWCtl.SWCtl"
		$b16 = "Shell.UIHelper"
		$b17 = "ShockwaveFlash.ShockwaveFlash"
		$b18 = "Skype.Detection"
		$b19 = "TDCCtl.TDCCtl"
		$b20 = "WMPlayer.OCX"
		$b21 = "rmocx.RealPlayer G2 Control"
		$b22 = "rmocx.RealPlayer G2 Control.1"

	condition:
		filesize < 1000000 and (
			(
				all of ($m*) and 
				2 of ($a*)
			) 
			or 8 of ($a*)
			or (
				5 of ($a*)
				and 13 of ($b*)
			)
		)

}


rule SUSP_obfuscated_JS_obfuscatorio
{
	meta:
	
		author      = "@imp0rtp3"
		description = "Detect JS obfuscation done by the js obfuscator (often malicious)"
		reference   = "https://obfuscator.io"

	strings:

		// Beggining of the script
		$a1 = "var a0_0x"
		$a2 = /var _0x[a-f0-9]{4}/
		
		// Strings to search By number of occurences
		$b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/
		$b2 =/[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/
		$b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/
		$b4 = /!0x1[^\d\w]/
		$b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/
		$b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/
		
		// generic strings often used by the obfuscator
		$c1 = "))),function(){try{var _0x"
		$c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$c3 = "['atob']=function("
		$c4 = ")['replace'](/=+$/,'');var"
		$c5 = "return!![]"
		$c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
		$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
		$c8 = "while(!![])"
		$c9 = "while (!![])"

		// Strong strings
		$d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/
				
	condition:
		$a1 at 0 or
		$a2 at 0 or
		(
			filesize<1000000 and
			(
				(#b1 + #b2) > (filesize \ 200) or
				#b3 > 1 or
				#b4 > 10 or
				#b5 > (filesize \ 2000) or
				#b6 > (filesize \ 200) or
				3 of ($c*) or
				$d1
			)
		)
}

rule apt_CN_Tetris_JS_advanced_1
{
	meta:
		author      = "@imp0rtp3"
		description = "Unique code from Jetriz, Swid & Jeniva of the Tetris framework"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"


	strings:
		$a1 = "var a0_0x"
		$b1 = /a0_0x[a-f0-9]{4}\('0x[0-9a-f]{1,3}'\)/
		$c1 = "))),function(){try{var _0x"
		$c2 = "=window)||void 0x0===_0x"
		$c3 = "){}});}();};window['$']&&window['$']()[a0_0x"
		$c4 = "&&!(Number(window['$']()[a0_0x"
		$c5 = "=function(){return!window['$']||!window['$']()[a0_0x" // second
		$c6 = "')]||Number(window['$']()[a0_0x"
		$c7 = "')]>0x3&&void 0x0!==arguments[0x3]?arguments[0x3]:document;"
		$d1 = "){if(opener&&void 0x0!==opener[" //not dep on a0
		$d2 = "&&!/loaded|complete/"
		$d3 = "')]=window['io']["
		$d4 = "==typeof console["
		$d5 = /=setInterval\(this\[[a-fx0-9_]{2,10}\([0-9a-fx']{1,8}\)\]\[[a-fx0-9_]{2,10}\([0-9a-fx']{1,8}\)\]\(this\),(0x1388|5000)\);}/
		$d6 = "['shift']());}};"
		$d7 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$d8 = "['atob']=function("
		$d9 = ")['replace'](/=+$/,'');var"
		$d10 = /\+=String\['fromCharCode'\]\(0xff&_?[0-9a-fx_]{1,10}>>\(\-(0x)?2\*/
		$e1 = "')](__p__)"
	condition:
	$a1 at 0 
	or (
		filesize<1000000
		and (
			#b1 > 2000
			or #e1 > 1 
			or 3 of ($c*)
			or 6 of ($d*) 
			or ( 	
				any of ($c*) 
				and 4 of ($d*)
			)
		)
	)
}

rule apt_CN_Tetris_JS_advanced_2
{
	meta:
		author      = "@imp0rtp3"
		description = "Strings used by Jetriz, Swid & Jeniva of the Tetris framework"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:
		$a1 = "SFRNTEFsbENvbGxlY3Rpb24=" // '#Socket receive,'
		$a2 = "Y2FuY2VsYWJsZQ==" // '#socket receive,'
		$a3 = "U29nb3U=" // '#task'
		$a4 = "U291cmNlQnVmZmVyTGlzdA==" // '/public/_images/'
		$a5 = "RE9NVG9rZW5MaXN0" // '/public/dependence/jquery/1.12.4/jquery.min.js'
		$a6 = "c2V0U3Ryb25n" // '/public/jquery.min.js?ver='
		$a7 = "ZWxlbQ==" // '/public/socket.io/socket.io.js'
		$a8 = "SW50MzI=" // '/sSocket'
		$a9 = "cmVzdWx0" // '/zSocket'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "TUFYX1NBRkVfSU5URUdFUg==" // 'AliApp(TB'
		$a12 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a13 = "X19wcm90b19f" // 'Body not allowed for GET or HEAD requests'
		$a14 = "Z2V0T3duUHJvcGVydHlTeW1ib2xz" // 'Chromium'
		$a15 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a16 = "emgtbW8=" // 'DOMStringList'
		$a17 = "cG93" // 'DataView'
		$a18 = "RmlsZUxpc3Q=" // 'EPSILON'
		$a19 = "YWNvc2g=" // 'FileReader'
		$a20 = "U3VibWl0" // 'Firebug'
		$a21 = "NS4x" // 'Firefox Focus'
		$a22 = "ZmluZEluZGV4" // 'FreeBSD'
		$a23 = "SW52YWxpZCBEYXRl" // 'FxiOS'
		$a24 = "ZGlzcGxheQ==" // 'HTMLSelectElement'
		$a25 = "YmFzZTY0RW5jb2Rl" // 'HeadlessChrome'
		$a26 = "RmxvYXQzMg==" // 'HuaweiBrowser'
		$a27 = "Y2xvbmU=" // 'Iceweasel'
		$a28 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a29 = "bGFuZw==" // 'IqiyiApp'
		$a30 = "Z2V0TGFuZw==" // 'LBBROWSER'
		$a31 = "c3BsaWNl" // 'Mb2345Browser'
		$a32 = "YXRhbmg=" // 'NEW GET JOB, [GET] URL='
		$a33 = "b25yZWFkeXN0YXRlY2hhbmdl" // 'NEW LocalStorage JOB, [LocalStorage] URL='
		$a34 = "QmFpZHU=" // 'NEW POST JOB, [POST] URL='
		$a35 = "PG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJJRT0=" // 'Number#toPrecision: incorrect invocation!'
		$a36 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a37 = "dXNlclNvY2tldElk" // 'PaintRequestList'
		$a38 = "UGFk" // 'PluginArray'
		$a39 = "MTEuMA==" // 'Promise-chain cycle'
		$a40 = "YWJvcnQ=" // 'QHBrowser'
		$a41 = "Ni41" // 'QQBrowser'
		$a42 = "Y29tbW9uMjM0NQ==" // 'QihooBrowser'
		$a43 = "TnVtYmVyLnRvRml4ZWQ6IGluY29ycmVjdCBpbnZvY2F0aW9uIQ==" // 'SNEBUY-APP'
		$a44 = "Y29uc3RydWN0b3IsaGFzT3duUHJvcGVydHksaXNQcm90b3R5cGVPZixwcm9wZXJ0eUlzRW51bWVyYWJsZSx0b0xvY2FsZVN0cmluZyx0b1N0cmluZyx2YWx1ZU9m" // 'SourceBufferList'
		$a45 = "aG9yaXpvbnRhbA==" // 'Symbian'
		$a46 = "Z2V0VVRDTWlsbGlzZWNvbmRz" // 'URLSearchParams'
		$a47 = "cmVzcG9uc2VUZXh0" // 'WebKitMutationObserver'
		$a48 = "P3Y9" // 'Wechat'
		$a49 = "Ni4y" // 'Weibo'
		$a50 = "NjA4NzgyMjBjMjVmYmYwMDM1Zjk4NzZj" // 'X-Request-URL'
		$a51 = "aXNDb25jYXRTcHJlYWRhYmxl" // 'XiaoMi'
		$a52 = "dG9JU09TdHJpbmc=" // 'YaBrowser'
		$a53 = "ZGVm" // '[object Int16Array]'
		$a54 = "Y29uY2F0" // '^.*2345Explorer\\/([\\d.]+).*$'
		$a55 = "YnJvd3Nlckxhbmd1YWdl" // '^.*BIDUBrowser[\\s\\/]([\\d.]+).*$'
		$a56 = "ZGVidWc=" // '^.*IqiyiVersion\\/([\\d.]+).*$'
		$a57 = "W29iamVjdCBVaW50OENsYW1wZWRBcnJheV0=" // '^.*SogouMobileBrowser\\/([\\d.]+).*$'
		$a58 = "Z2V0" // '^Mozilla\\/\\d.0 \\(Windows NT ([\\d.]+);.*$'
		$a59 = "c3RvcA==" // '__FILE__'
		$a60 = "TUFYX1ZBTFVF" // '__core-js_shared__'
		$a61 = "Y3Jvc3NPcmlnaW4=" // '__devtools__'
		$a62 = "SWNlYXBl" // '__p__'
		$a63 = "Ym9sZA==" // '__pdr__'
		$a64 = "dHJpbQ==" // '__proto__'
		$a65 = "TnVtYmVyI3RvUHJlY2lzaW9uOiBpbmNvcnJlY3QgaW52b2NhdGlvbiE=" // '_initBody'
		$a66 = "cmVtb3ZlQ2hpbGQ=" // 'addEventListener'
		$a67 = "OS4w" // 'addIEMeta'
		$a68 = "ZGV2dG9vbHNjaGFuZ2U=" // 'addNoRefererMeta'
		$a69 = "bmV4dExvYw==" // 'appendChild'
		$a70 = "OTg2" // 'application/360softmgrplugin'
		$a71 = "aXNHZW5lcmF0b3JGdW5jdGlvbg==" // 'application/hwepass2001.installepass2001'
		$a72 = "ZW4t" // 'application/vnd.chromium.remoting-viewer'
		$a73 = "UHJlc3Rv" // 'baiduboxapp'
		$a74 = "c29tZQ==" // 'browserLanguage'
		$a75 = "Q3JPUw==" // 'callback'
		$a76 = "U05FQlVZLUFQUA==" // 'charCodeAt'
		$a77 = "Vml2bw==" // 'clearImmediate'
		$a78 = "RGlzcGF0Y2g=" // 'codePointAt'
		$a79 = "ZXhwb3J0cw==" // 'copyWithin'
		$a80 = "QlJFQUs=" // 'credentials'
		$a81 = "a2V5cw==" // 'crossOrigin'
		$a82 = "TWVzc2FnZUNoYW5uZWw=" // 'crossOriginJsonp'
		$a83 = "YWRkRXZlbnRMaXN0ZW5lcg==" // 'devtoolschange'
		$a84 = "c2F2ZQ==" // 'executing'
		$a85 = "dG9KU09O" // 'fakeScreen'
		$a86 = "d2ViZHJpdmVy" // 'fastKey'
		$a87 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'
		$a88 = "Xi4qT1MgKFtcZF9dKykgbGlrZS4qJA==" // 'g__Browser'
		$a89 = "c2NyaXB0VmlhV2luZG93" // 'getAllResponseHeaders'
		$a90 = "Q2xpZW50UmVjdExpc3Q=" // 'getHighestZindex'
		$a91 = "dG9QcmltaXRpdmU=" // 'getOwnPropertyDescriptors'
		$a92 = "bGlua3M=" // 'handleLS'
		$a93 = "MTEuMQ==" // 'handleMessage'
		$a94 = "RGF0YVRyYW5zZmVySXRlbUxpc3Q=" // 'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
		$a95 = "Zm9udA==" // 'heartBeats'
		$a96 = "Q1NTU3R5bGVEZWNsYXJhdGlvbg==" // 'heartBeatsForLS'
		$a97 = "ZW5jdHlwZQ==" // 'heartbeat'
		$a98 = "W29iamVjdCBXaW5kb3dd" // 'hiddenIframe'
		$a99 = "c3Vic3Ry" // 'hiddenImg'
		$a100 = "aW5uZXJXaWR0aA==" // 'iQiYi'
		$a101 = "SW5maW5pdHk=" // 'imgUrl2Base64'
		$a102 = "ZnJvbQ==" // 'importScripts'
		$a103 = "c29ja2V0" // 'initSocket'
		$a104 = "bWVzc2FnZQ==" // 'inspectSource'
		$a105 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a106 = "b3NWZXJzaW9u" // 'isConcatSpreadable'
		$a107 = "YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkO2NoYXJzZXQ9VVRGLTg=" // 'isExtensible'
		$a108 = "dW5kZWZpbmVk" // 'isRender'
		$a109 = "Xi4qTWIyMzQ1QnJvd3NlclwvKFtcZC5dKykuKiQ=" // 'isView'
		$a110 = "UmVnRXhwIGV4ZWMgbWV0aG9kIHJldHVybmVkIHNvbWV0aGluZyBvdGhlciB0aGFuIGFuIE9iamVjdCBvciBudWxs" // 'like Mac OS X'
		$a111 = "aXNJbnRlZ2Vy" // 'link[href="'
		$a112 = "Q3VzdG9tRXZlbnQ=" // 'link[rel=stylesheet]'
		$a113 = "Zm9udHNpemU=" // 'localStorage'
		$a114 = "NC4w" // 'meta[name="referrer"][content="always"]'
		$a115 = "c2lnbmFs" // 'noRefererJsonp'
		$a116 = "aGFzSW5zdGFuY2U=" // 'onFreeze'
		$a117 = "UUhCcm93c2Vy" // 'onabort'
		$a118 = "Y3JlYXRlSGlkZGVuRWxlbWVudA==" // 'onerror'
		$a119 = "aW1hZ2UvcG5n" // 'onload'
		$a120 = "cGx1Z2luVHlwZQ==" // 'onloadend'
		$a121 = "Q2Fubm90IGNhbGwgYSBjbGFzcyBhcyBhIGZ1bmN0aW9u" // 'onmessage'
		$a122 = "dHJhaWxpbmc=" // 'onreadystatechange'
		$a123 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a124 = "cmV0dXJuIChmdW5jdGlvbigpIA==" // 'pluginId'
		$a125 = "b25tZXNzYWdl" // 'pluginType'
		$a126 = "TnVtYmVy" // 'processGET'
		$a127 = "dGV4dGFyZWE=" // 'processLS'
		$a128 = "aXRlcmF0b3I=" // 'processPOST'
		$a129 = "Ni42" // 'projectId'
		$a130 = "TW9iaQ==" // 'pushxhr'
		$a131 = "MzYw" // 'readAsDataURL'
		$a132 = "T3BlcmE=" // 'reduceRight'
		$a133 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a134 = "ZGV2aWNl" // 'return (function() '
		$a135 = "ZmV0Y2g=" // 'return new F('
		$a136 = "Xi4qVmVyc2lvblwvKFtcZC5dKykuKiQ=" // 'rewriteLinks'
		$a137 = "ZG9uZQ==" // 'sSocket'
		$a138 = "TE4y" // 'scriptViaIframe'
		$a139 = "YWxs" // 'scriptViaWindow'
		$a140 = "MjAwMA==" // 'setLS'
		$a141 = "ZmFpbA==" // 'setSL'
		$a142 = "dHJhY2U=" // 'stringify'
		$a143 = "Y29tcGxldGlvbg==" // 'suspendedStart'
		$a144 = "bmV4dA==" // 'toISOString'
		$a145 = "Z19fQnJvd3Nlcg==" // 'userSocketId'
		$a146 = "b25yZWplY3Rpb25oYW5kbGVk" // 'withCredentials'
		$a147 = "VW5kZWZpbmVk" // 'xsrf'
		$a148 = "Q2hyb21lLzY2" // 'zIndex'
		$a149 = "Y2FuY2Vs" // 'zh-mo'
		$a150 = "cmVzdWx0TmFtZQ==" // 'zh-tw'
		$a151 = "YXBwbGljYXRpb24vbW96aWxsYS1ucHFpaG9vcXVpY2tsb2dpbg==" // '{}.constructor("return this")( )'
		$a152 = "YXJn" // ' 2020 Denis Pushkarev (zloirock.ru)'
		$a153 = "U3ltYm9sIGlzIG5vdCBhIGNvbnN0cnVjdG9yIQ==" // 'FileReader'
		$b1 = "#Socket receive,"
		$b2 = "#socket receive,"
		$b3 = "'#task'"
		$b4 = "/public/_images/"
		$b5 = "/public/dependence/jquery/1.12.4/jquery.min.js"
		$b6 = "/public/jquery.min.js?ver="
		$b7 = "/public/socket.io/socket.io.js"
		$b8 = "/sSocket"
		$b9 = "/zSocket"
		$b10 = "<script>document.F=Object</script>"
		$b11 = "AliApp(TB"
		$b12 = "BIDUBrowser"
		$b13 = "Body not allowed for GET or HEAD requests"
		$b14 = "Chromium"
		$b15 = "ClientRectList"
		$b16 = "DOMStringList"
		$b17 = "DataView"
		$b18 = "EPSILON"
		$b19 = "FileReader"
		$b20 = "Firebug"
		$b21 = "Firefox Focus"
		$b22 = "FreeBSD"
		$b23 = "FxiOS"
		$b24 = "HTMLSelectElement"
		$b25 = "HeadlessChrome"
		$b26 = "HuaweiBrowser"
		$b27 = "Iceweasel"
		$b28 = "Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array"
		$b29 = "IqiyiApp"
		$b30 = "LBBROWSER"
		$b31 = "Mb2345Browser"
		$b32 = "NEW GET JOB, [GET] URL="
		$b33 = "NEW LocalStorage JOB, [LocalStorage] URL="
		$b34 = "NEW POST JOB, [POST] URL="
		$b35 = "Number#toPrecision: incorrect invocation!"
		$b36 = "OnlineTimer"
		$b37 = "PaintRequestList"
		$b38 = "PluginArray"
		$b39 = "Promise-chain cycle"
		$b40 = "QHBrowser"
		$b41 = "QQBrowser"
		$b42 = "QihooBrowser"
		$b43 = "SNEBUY-APP"
		$b44 = "SourceBufferList"
		$b45 = "Symbian"
		$b46 = "URLSearchParams"
		$b47 = "WebKitMutationObserver"
		$b48 = "Wechat"
		$b49 = "Weibo"
		$b50 = "X-Request-URL"
		$b51 = "XiaoMi"
		$b52 = "YaBrowser"
		$b53 = "[object Int16Array]"
		$b54 = "^.*2345Explorer\\/([\\d.]+).*$"
		$b55 = "^.*BIDUBrowser[\\s\\/]([\\d.]+).*$"
		$b56 = "^.*IqiyiVersion\\/([\\d.]+).*$"
		$b57 = "^.*SogouMobileBrowser\\/([\\d.]+).*$"
		$b58 = "^Mozilla\\/\\d.0 \\(Windows NT ([\\d.]+);.*$"
		$b59 = "__FILE__"
		$b60 = "__core-js_shared__"
		$b61 = "__devtools__"
		$b62 = "__p__"
		$b63 = "__pdr__"
		$b64 = "__proto__"
		$b65 = "_initBody"
		$b66 = "addEventListener"
		$b67 = "addIEMeta"
		$b68 = "addNoRefererMeta"
		$b69 = "appendChild"
		$b70 = "application/360softmgrplugin"
		$b71 = "application/hwepass2001.installepass2001"
		$b72 = "application/vnd.chromium.remoting-viewer"
		$b73 = "baiduboxapp"
		$b74 = "browserLanguage"
		$b75 = "callback"
		$b76 = "charCodeAt"
		$b77 = "clearImmediate"
		$b78 = "codePointAt"
		$b79 = "copyWithin"
		$b80 = "credentials"
		$b81 = "crossOrigin"
		$b82 = "crossOriginJsonp"
		$b83 = "devtoolschange"
		$b84 = "executing"
		$b85 = "fakeScreen"
		$b86 = "fastKey"
		$b87 = "finallyLoc"
		$b88 = "g__Browser"
		$b89 = "getAllResponseHeaders"
		$b90 = "getHighestZindex"
		$b91 = "getOwnPropertyDescriptors"
		$b92 = "handleLS"
		$b93 = "handleMessage"
		$b94 = "hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables"
		$b95 = "heartBeats"
		$b96 = "heartBeatsForLS"
		$b97 = "heartbeat"
		$b98 = "hiddenIframe"
		$b99 = "hiddenImg"
		$b100 = "iQiYi"
		$b101 = "imgUrl2Base64"
		$b102 = "importScripts"
		$b103 = "initSocket"
		$b104 = "inspectSource"
		$b105 = "ipec"
		$b106 = "isConcatSpreadable"
		$b107 = "isExtensible"
		$b108 = "isRender"
		$b109 = "isView"
		$b110 = "like Mac OS X"
		$b111 = "link[href=\""
		$b112 = "link[rel=stylesheet]"
		$b113 = "localStorage"
		$b114 = "meta[name=\"referrer\"][content=\"always\"]"
		$b115 = "noRefererJsonp"
		$b116 = "onFreeze"
		$b117 = "onabort"
		$b118 = "onerror"
		$b119 = "onload"
		$b120 = "onloadend"
		$b121 = "onmessage"
		$b122 = "onreadystatechange"
		$b123 = "onrejectionhandled"
		$b124 = "pluginId"
		$b125 = "pluginType"
		$b126 = "processGET"
		$b127 = "processLS"
		$b128 = "processPOST"
		$b129 = "projectId"
		$b130 = "pushxhr"
		$b131 = "readAsDataURL"
		$b132 = "reduceRight"
		$b133 = "regeneratorRuntime = r"
		$b134 = "return (function() "
		$b135 = "return new F("
		$b136 = "rewriteLinks"
		$b138 = "scriptViaIframe"
		$b139 = "scriptViaWindow"
		$b140 = "setLS"
		$b141 = "setSL"
		$b142 = "stringify"
		$b143 = "suspendedStart"
		$b144 = "toISOString"
		$b145 = "userSocketId"
		$b146 = "withCredentials"
		$b147 = "xsrf"
		$b148 = "zIndex"
		$b149 = "zh-mo"
		$b150 = "zh-tw"
		$b151 = "{}.constructor(\"return this\")( )"
		$b152 = "\xc2\xa9 2020 Denis Pushkarev (zloirock.ru)"
		$b153 = "\xE4\xB8\x8D\xE6\x94\xAF\xE6\x8C\x81FileReader"

	condition:
		filesize < 1000000 and (
			25 of ($a*) or
			75 of ($b*)
		)

}

rule apt_CN_Tetrisplugins_JS    
{
	meta:
		author      = "@imp0rtp3"
		description = "Code and strings of plugins from the Tetris framework loaded by Swid"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:


		// Really unique strings
		$a1 = "this.plugin = plugin; // \xE8\x87\xAA\xE5\x8A\xA8\xE8\xBF\x90\xE8\xA1\x8C"
		$a2 = "[Success]用户正在使用\\x20Tor\\x20网络"
		$a3 = "(0xbb8);this['socketWatcher'](0xbb9);this["
		$a4 = "a2869674571f77b5a0867c3d71db5856"
		$a5 = "\\x0a\\x20\\x20var\\x20data\\x20=\\x20{}\\x0a\\x20\\x20window.c\\x20=\\x200\\x0a\\x20\\x20script2\\x20=\\x20document.createElement(\\x22script\\x22)\\x0a\\x20\\x20script2.async\\x20=\\x20true\\x0a\\x20\\x20script2.src\\x20=\\x20\\x22"
		$a6 = "{isPluginCallback:\\x20true,\\x20data,\\x20plugin:\\x20'"
		$a7 = "\\x20\\x22*\\x22)\\x0a\\x20\\x20}\\x0a\\x20\\x20document.documentElement.appendChild("
		
		// Still quite unique, but FP possible
		$b1 = "String(str).match(/red\">(.*?)<\\/font>/)"
		$b2 = "['data']);}};}},{'key':'run','value':function _0x"
		$b3 = "},{'plugin':this['plugin'],'save':!![],'type':_typeof("
		$b4 = "Cannot\\x20call\\x20a\\x20class\\x20as\\x20a\\x20function"
		$b5 = "The\\x20command\\x20is\\x20sent\\x20successfully,\\x20wait\\x20for\\x20the\\x20result\\x20to\\x20return"
		$b6 = "getUserMedia\\x20is\\x20not\\x20implemented\\x20in\\x20this\\x20browser"
		$b7 = "{'autoplay':'true'},!![]);setTimeout(function(){return $('#'+"
		$b8 = "keyLogger($('input'));\n        keyLogger($('textarea'));"
		$b9 = "api.loadJS(\"\".concat(api.base.baseUrl"
		$b10 = "\"\".concat(imgUrls[i], \"?t=\""
		$b11 = "key: \"report\",\n      value: function report(data) {\n        return this.api.callback"
		$b12 = "that.api.base.debounce("
		$b13 = "'className','restOfNavigator','push'"
		$b14 = ";};'use strict';function _typeof("
		
		// Rare strings, but not unique
		$c1 = "/public/dependence/jquery"
		$c2 = "'http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png'"
		$c3 = "'163.com not login';"
		$c4 = "'ws://localhost:'"
		$c5 = "function _typeof(obj) { \"@babel/helpers - typeof\"; "
		$c6 = "'socketWatcher'"
		$c7 = "['configurable']=!![];"
		$c8 = "')]({'status':!![],'data':_0x"
		$c9 = "')]={'localStorage':'localStorage'in window?window[_0x"
		$c10 = "Browser not supported geolocation.');"
		$c11 = "')]({'status':!![],'msg':'','data':_0x"
		$c12 = "var Plugin = /*#__PURE__*/function () {"
		
		// The TA uses the use strict in all his plugins
		$use_strict1 = "\"use strict\";"
		$use_strict2 = "'use strict';"

		// Some of the same strings in base64, in case the attacker change their obfuscation there
		$e1 = "Cannot\x20call\x20a\x20class\x20as\x20a\x20function" base64
		$e2 = "The\x20command\x20is\x20sent\x20successfully,\x20wait\x20for\x20the\x20result\x20to\x20return" base64
		$e3 = "getUserMedia\x20is\x20not\x20implemented\x20in\x20this\x20browser" base64
		$e4 = "http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png" base64
		$e5 = "/public/dependence/jquery" base64
		$e6 = "\x20\x22*\x22)\x0a\x20\x20}\x0a\x20\x20document.documentElement.appendChild(" base64
		$e7 = "[Success]\xE7\x94\xA8\xE6\x88\xB7\xE6\xAD\xA3\xE5\x9C\xA8\xE4\xBD\xBF\xE7\x94\xA8\x5C\x5C\x78\x32\x30\x54\x6F\x72" base64
		$e8 = "\x0a\x20\x20var\x20data\x20=\x20{}\x0a\x20\x20window.c\x20=\x200\x0a\x20\x20script2\x20=\x20document.createElement(\x22script\x22)\x0a\x20\x20script2.async\x20=\x20true\x0a\x20\x20script2.src\x20=\x20\x22"  base64
		$e9 = "{isPluginCallback:\x20true,\x20data,\x20plugin:\x20" base64
		
	condition:
		filesize < 1000000 
		and (
			any of ($a*) 
			or 2 of ($b*)
			or 4 of ($c*)
			or 2 of ($e*)
			or(
				any of ($use_strict*)
				and(
					(
						any of ($b*) 
						and 2 of ($c*)
					)
					or any of ($e*)
				)
			)
		)
}