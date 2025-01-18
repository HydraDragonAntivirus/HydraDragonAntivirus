rule Adfind
{
    meta:
        id = "369wFVCBXsVYywgZZJhUjW"
        fingerprint = "296292e4e665d7eb2d36b2ad655d451cdf89bc27d2705bb8cb97fa34afcd16cb"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adfind, a Command line Active Directory query tool."
        category = "HACKTOOL"
        tool = "ADFIND"
        mitre_att = "S0552"
        reference = "http://www.joeware.net/freetools/tools/adfind/"


    strings:
        $ = "E:\\DEV\\cpp\\vs\\AdFind\\AdFind\\AdFind.cpp" ascii wide
        $ = "adfind.cf" ascii wide
        $ = "adfind -" ascii wide
        $ = "adfind /" ascii wide
        $ = "you have encountered a STAT binary blob that" ascii wide

    condition:
        any of them
}rule Andromeda
{
    meta:
        id = "66EiRJfwdRpNnHru6KDjKX"
        fingerprint = "45a5315e4ffe5156ce4a7dc8e2d6e27d6152cd1d5ce327bfa576bf0c4a4767d8"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2022-01-24"
        last_modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Andromeda aka Gamarue botnet."
        category = "MALWARE"
        malware = "ANDROMEDA"
        malware_type = "WORM"



    strings:
		//IndexerVolumeGuid
        $ = { 8d ?? dc fd ff ff 50 8d ?? d8 fd ff ff 50 e8 ?? ?? ?? ?? 8a 00 53 68 ?? ?? ?? ?? 56
    ff b? ?? ?? ?? ?? a2 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 18 53 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53
    53 ff 15 ?? ?? ?? ?? ff b? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 f8
    ff 74 ?? 6a 01 50 ff 15 ?? ?? ?? ?? }
        $ = { 83 c4 10 ff b? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? ?? ?? ?? ff b?
    ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? }


		/*
		MOV        DL ,byte ptr SS :[EAX  + EBP *0x1  + 0xffffff00 ]
		MOV        DH ,byte ptr SS :[EBX  + EBP *0x1  + 0xffffff00 ]
		MOV        byte ptr SS :[EAX  + EBP *0x1  + 0xffffff00 ],DH
		MOV        byte ptr SS :[EBX  + EBP *0x1  + 0xffffff00 ],DL
		*/
        $ = { 36 8a 94 28 00 ff ff ff 02 da 36 8a b4 2b 00 ff ff ff 36 88 b4 28 00 ff ff ff 36 88 94 2b 00 ff ff ff }

    condition:
        any of them
}
rule ArechClient
{
    meta:
        id = "1POsZzKWdklwDRUysnEJ9J"
        fingerprint = "949f1c6596fffe0aca581e61bcc522e70775ad16c651875539c32d6de6801729"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ArechClient, infostealer."
        category = "MALWARE"
        malware = "ARECHCLIENT"
        malware_type = "INFOSTEALER"


    strings:
        $ = "is_secure" ascii wide
        $ = "encrypted_value" ascii wide
        $ = "host_keyexpires_utc" ascii wide

    condition:
        all of them
}import "dotnet"

rule ArechClient_Campaign_July2021
{
    meta:
        id = "16N9HHtspErd7pE2A261Mh"
        fingerprint = "971fcef8b604c185c14af001633a3f83297d183f47620a9c4fc014815b26a28f"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ArechClient stealer's July 2021 campaign."
        category = "MALWARE"
        malware = "ARECHCLIENT"
        malware_type = "INFOSTEALER"
        reference = "https://twitter.com/bcrypt/status/1420471176137113601"


    condition:
        dotnet.guids[0]=="10867a7d-8f80-4d52-8c58-47f5626e7d52" or dotnet.guids[0]=="7596afea-18b9-41f9-91dd-bee131501b08"
}rule AuroraStealer
{
meta:
	id = "6Z1CVWsCBgJV6aRbfDFvlr"
	fingerprint = "06f893451d74f7cc924b9988443338ed9d86d8afb3b1facdfee040bce0c45289"
	version = "1.0"
	first_imported = "2023-05-26"
	last_modified = "2023-05-26"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Aurora Stealer."
	category = "MALWARE"
	malware = "Aurora Stealer"
	reference = " https://malpedia.caad.fkie.fraunhofer.de/details/win.aurora_stealer"
  
strings:
	$ = "main.(*DATA_BLOB).ToByteArray" ascii wide
	$ = "main.base64Decode" ascii wide
	$ = "main.base64Encode" ascii wide
	$ = "main.Capture" ascii wide
	$ = "main.CaptureRect" ascii wide
	$ = "main.compresss" ascii wide
	$ = "main.ConnectToServer" ascii wide
	$ = "main.countupMonitorCallback" ascii wide
	$ = "main.CreateImage" ascii wide
	$ = "main.enumDisplayMonitors" ascii wide
	$ = "main.FileExsist" ascii wide
	$ = "main.getCPU" ascii wide
	$ = "main.getDesktopWindow" ascii wide
	$ = "main.GetDisplayBounds" ascii wide
	$ = "main.getGPU" ascii wide
	$ = "main.GetInfoUser" ascii wide
	$ = "main.getMasterKey" ascii wide
	$ = "main.getMonitorBoundsCallback" ascii wide
	$ = "main.getMonitorRealSize" ascii wide
	$ = "main.GetOS" ascii wide
	$ = "main.Grab" ascii wide
	$ = "main.MachineID" ascii wide
	$ = "main.NewBlob" ascii wide
	$ = "main.NumActiveDisplays" ascii wide
	$ = "main.PathTrans" ascii wide
	$ = "main.RandStringBytes" ascii wide
	$ = "main.SendToServer_NEW" ascii wide
	$ = "main.SetUsermame" ascii wide
	$ = "main.sysTotalMemory" ascii wide
	$ = "main.xDecrypt" ascii wide
	$ = "main.Zip" ascii wide
	$ = "type..eq.main.Browser_G" ascii wide
	$ = "type..eq.main.Crypto_G" ascii wide
	$ = "type..eq.main.DATA_BLOB" ascii wide
	$ = "type..eq.main.FileGrabber_G" ascii wide
	$ = "type..eq.main.FTP_G" ascii wide
	$ = "type..eq.main.Grabber" ascii wide
	$ = "type..eq.main.ScreenShot_G" ascii wide
	$ = "type..eq.main.Steam_G" ascii wide
	$ = "type..eq.main.STRUSER" ascii wide
	$ = "type..eq.main.Telegram_G" ascii wide
	
condition:
	25 of them
}
rule AutoIT_Compiled
{
    meta:
        id = "1HD8y9jsBZi1HDN82XCpZx"
        fingerprint = "7d7623207492860e4196e8c8a493b874bb3042c83f19e61e1d958e79a09bc8f8"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compiled AutoIT script (as EXE)."
        category = "MALWARE"

    strings:
        $ = "#OnAutoItStartRegister" ascii wide
        $ = "#pragma compile" ascii wide
        $ = "/AutoIt3ExecuteLine" ascii wide
        $ = "/AutoIt3ExecuteScript" ascii wide
        $ = "/AutoIt3OutputDebug" ascii wide
        $ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
        $ = ">>>AUTOIT SCRIPT<<<" ascii wide
        $ = "This is a third-party compiled AutoIt script." ascii wide

    condition:
        uint16(0)==0x5A4D and any of them
}

rule AutoIT_Script
{
    meta:
        id = "vpilwARgwZCuMLJPuubYB"
        fingerprint = "87dfe76f69bd344860faf3dc46f16b56a2c86a0a3f3763edf8f51860346a16c2"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2023-10-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies AutoIT script."
        category = "MALWARE"

    strings:
        $ = "#OnAutoItStartRegister" ascii wide
        $ = "#pragma compile" ascii wide
        $ = "/AutoIt3ExecuteLine" ascii wide
        $ = "/AutoIt3ExecuteScript" ascii wide
        $ = "/AutoIt3OutputDebug" ascii wide
        $ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
        $ = ">>>AUTOIT SCRIPT<<<" ascii wide
        $ = "This is a third-party compiled AutoIt script." ascii wide
        $ = "AU3!EA06" ascii wide

    condition:
        uint16(0)!=0x5A4D and any of them
}
rule Avaddon
{
    meta:
        id = "gzIxctaiGZf4jXkwWO0BR"
        fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088f"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        malware_type = "RANSOMWARE"
        mitre_att = "S0640"

    strings:
        $s1 = "\"ext\":" ascii wide
        $s2 = "\"rcid\":" ascii wide
        $s3 = "\"hdd\":" ascii wide
        $s4 = "\"name\":" ascii wide
        $s5 = "\"size\":" ascii wide
        $s6 = "\"type\":" ascii wide
        $s7 = "\"lang\":" ascii wide
        $s8 = "\"ip\":" ascii wide
        $code = { 83 7f 14 10 8b c7 c7 4? ?? 00 00 00 00 72 ?? 8b 07 6a 00 6a 00 
    8d ?? f8 51 6a 00 6a 01 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 56 
        8b 7? ?? ff 15 ?? ?? ?? ?? 56 6a 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 
        f6 74 ?? 83 7f 14 10 72 ?? 8b 3f }

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or $code)
}rule AveMaria
{
    meta:
        id = "7kTjKOPEjKKZRVTPh5LCPf"
        fingerprint = "6cf820532d1616bf7e0a16d2ccf0fb4c31df30e775fd9de1622ac840f55b2fee"
        version = "1.0"
        creation_date = "2020-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies AveMaria aka WarZone RAT."
        category = "MALWARE"
        malware = "WARZONERAT"
        malware_type = "RAT"
        mitre_att = "S0534"


    strings:
        $ = "AVE_MARIA" ascii wide
        $ = "Ave_Maria Stealer OpenSource" ascii wide
        $ = "Hey I'm Admin" ascii wide
        $ = "WM_DISP" ascii wide fullword
        $ = "WM_DSP" ascii wide fullword
        $ = "warzone160" ascii wide

    condition:
        3 of them
}rule BazarBackdoor
{
    meta:
        id = "457CJ7xNoBZJ2ChWuy0zgq"
        fingerprint = "b16f9a0651d90b68dced444c7921fd594b36f7672c29daf9fcbdb050f7655519"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Bazar backdoor."
        category = "MALWARE"
        malware = "BAZAR BACKDOOR"
        malware_type = "BACKDOOR"
        mitre_att = "S0534"
        reference = "https://www.bleepingcomputer.com/news/security/bazarbackdoor-trickbot-gang-s-new-stealthy-network-hacking-malware/"


    strings:
        $ = { c7 44 ?? ?? 6d 73 67 3d c7 44 ?? ?? 6e 6f 20 66 c7 44 ?? ?? 69 6c 65 00  }
        $ = { c7 44 ?? ?? 43 4e 20 3d 4? 8b f1 4? 89 b? ?? ?? ?? ?? 33 d2 4? 89 b? ?? ?? ?? ?? 4? 8d ?? ?4 60 4? 89 b? ?? ?? ?? ?? 4? 8d 7f 10 c7 44 ?? ?? 20 6c 6f 63 4? 8b c7 c7 44 ?? ?? 61 6c 68 6f 4? 8b df 66 c7 44 ?? ?? 73 74  }

    condition:
        any of them
}rule BazarLoader
{
    meta:
        id = "71rkxLlpnZn1Wd8IRiqeno"
        fingerprint = "3bf045c85aedaf5e7ddaba5c8d8d0054615d1e24ab40bb9ba295b04693a95b69"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies BazarLoader."
        category = "MALWARE"
        malware_type = "LOADER"
        malware = "BAZARLOADER"
        reference = "https://www.bleepingcomputer.com/news/security/bazarbackdoor-trickbot-gang-s-new-stealthy-network-hacking-malware/"


    strings:
        $code = { 4? 89 05 69 8f 03 00 4? 85 c0 0f 84 e3 fe ff ff 4? 8b 05 01 e3 02 00 4? 89 85 e0 00 00 00 4? 8b 05 fb 
    e2 02 00 4? 89 85 e8 00 00 00 4? c7 85 d0 00 00 00 0f 00 00 00 4? 89 a5 c8 00 00 00 4? 88 a5 b8 00 00 00 4? 8d 
    44 ?4 40 4? 8d 15 77 e2 02 00 4? 8d 8d b8 00 00 00 e8 ca df ff ff 90 4? c7 45 58 0f 00 00 00 4? 89 65 50 4? 88 
    65 40 4? 8d 44 ?4 07 4? 8d 15 36 e2 02 00 4? 8d 4d 40 e8 a4 df ff ff 90 4? c7 45 08 0f 00 00 00 4? 89 65 00 4? 
    88 65 f0 4? 8d 44 ?4 0b 4? 8d 15 00 e2 02 00 }
        $pdb1 = "C:\\Users\\User\\Desktop\\2010\\14.4.20\\Test_64\\SEED\\Release\\SEED.pdb" ascii wide
        $pdb2 = "D:\\projects\\source\\repos\\7\\bd7 v2\\Bin\\x64\\Release_nologs\\bd7_x64_release_nologs.pdb" ascii wide

    condition:
        $code or any of ($pdb*)
}rule BlackKingDom
{
    meta:
        id = "su4arxDGFAZfSHRVAv689"
        fingerprint = "504f4b0c26223ecc9af94b8e95cc80b777ba25ced07af89192e1777895460b2e"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies (decompiled) Black KingDom ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"

    strings:
        $ = "BLACLIST" ascii wide
        $ = "Black KingDom" ascii wide
        $ = "FUCKING_WINDOW" ascii wide
        $ = "PleasStopMe" ascii wide
        $ = "THE AMOUNT DOUBLED" ascii wide
        $ = "WOWBICH" ascii wide
        $ = "clear_logs_plz" ascii wide
        $ = "decrypt_file.TxT" ascii wide
        $ = "disable_Mou_And_Key" ascii wide
        $ = "encrypt_file" ascii wide
        $ = "for_fortnet" ascii wide
        $ = "start_encrypt" ascii wide
        $ = "where_my_key" ascii wide

    condition:
        3 of them
}rule BroEx
{
meta:
	id = "5MNXppaMBFMS0DMQ63eCJO"
	fingerprint = "8eea2d3d8d4e8ca6ef89d474232d1117e2a5a5b4c714b4c82493293f31e4f2c6"
	version = "1.0"
	first_imported = "2023-09-18"
	last_modified = "2023-09-18"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Detects BroEx, a type of agressive adware."
	category = "MALWARE"
	malware = "BROEX"
	malware_type = "ADWARE"
	hash = "7f103012a143b9e358087cf94dbdd160362a57e5ebc65c560e352ac7541bd80e"

strings:
	//PDB
	$pdb = "I:\\Repository2\\test\\Project21\\event\\Release\\event.pdb" ascii wide
	
	//Mutants
	$mut1 = "Global\\A6A161D8-150E-46A1-B7EC-18E4CB58C6D2" ascii wide
	$mut2 = "Global\\D80D9D78-BCDA-482C-98F2-C38991A8CA3" ascii wide
	$mut3 = "Global\\8D13D07B-A758-456A-A215-0518F1268C2A" ascii wide
	
	//Launch
	$browser1 = "main -c rbrowser chrome" ascii wide
	$browser2 = "main -c rbrowser msedge" ascii wide
	
	//Service names
	$svc1 = "WimsysUpdaterService" ascii wide
	$svc2 = "WimsysService" ascii wide
	$svc3 = "WimsysServiceX64" ascii wide
	
	/*
	pvVar1 = (void *)0x0;
	param_1[3] = (void *)0x7;
	param_1[2] = (void *)0x0;
	*(undefined2 *)param_1 = 0;
	if (*(short *)param_2 != 0) {
	pvVar1 = (void *)0xffffffffffffffff;
	*/
	$str_decode = { 4? 53 4? 83 ec 20 4? 33 c0 4? c7 41 18 07 00 00 00 4? 8b d9 4? 89 41 10 66 4? 89 01 66 4? 39 02 74 11 4? 83 c8 ff  }

condition:
	uint16(0) == 0x5a4d and ($pdb or 2 of ($mut*) or all of ($browser*) 
	or 2 of ($svc*) or $str_decode)
}
rule Confucius_B
{
    meta:
        id = "3AaavteplEPTLc29oIVtzm"
        fingerprint = "f7a7224bfdbb79208776c856eb05a59ed75112376d0d3b28776305efc94c0414"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Confucius malware."
        category = "MALWARE"
        malware = "CONFUCIUS"
        malware_type = "BACKDOOR"
        reference = "https://unit42.paloaltonetworks.com/unit42-confucius-says-malware-families-get-further-by-abusing-legitimate-websites/"


    strings:
        $ = "----BONE-79A8DE0E314C50503FF2378aEB126363-" ascii wide
        $ = "----MUETA-%.08x%.04x%.04x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x-" ascii wide
        $ = "C:\\Users\\DMITRY-PC\\Documents\\JKE-Agent-Win32\\JKE_Agent_DataCollectorPlugin\\output\\Debug\\JKE_Agent_DumbTestPlugin.dll" ascii wide

    condition:
        any of them
}import "pe"

rule Cotx_RAT
{
    meta:
        id = "44kYl6i8SEYFPSxi2Q3Lz3"
        fingerprint = "47f671933c49fabc22117ef5e877efb33ba7fc0c437f6be3750ecca7cd27816a"
        version = "1.0"
        creation_date = "2019-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Cotx RAT."
        category = "MALWARE"
        malware = "COTX"
        malware_type = "RAT"
        reference = "https://www.proofpoint.com/us/threat-insight/post/chinese-apt-operation-lagtime-it-targets-government-information-technology"

    strings:
        $ = "%4d-%02d-%02d %02d:%02d:%02d" ascii wide
        $ = "%hs|%hs|%hs|%hs|%hs|%hs|%hs" ascii wide
        $ = "%hs|%s|%hs|%s|%s|%s|%s|%s|%s|%s|%hs" ascii wide
        $ = "%s;%s;%s;%.2f GB;%.2f GB|" ascii wide
        $ = "Cmd shell is not running,or your cmd is error!" ascii wide
        $ = "Domain:    [%s]" ascii wide
        $ = "Error:Cmd file not exists!" ascii wide
        $ = "Error:Create read pipe error!" ascii wide
        $ = "Error:No user is logoned!" ascii wide
        $ = "Error:You have in a shell,please exit first!" ascii wide
        $ = "Error:You have in a shell,please exit it first!" ascii wide
        $ = "Error:cmd.exe not exist!" ascii wide
        $ = "LogonUser: [%s]" ascii wide
        $ = "WriteFile session error!" ascii wide
        $ = "You have no permission to write on" ascii wide
        $ = "cannot delete directory:" ascii wide
        $ = "cannot delete file:" ascii wide
        $ = "cannot upload file to %s" ascii wide
        $ = "copy failed:" ascii wide
        $ = "exec failed:" ascii wide
        $ = "exec ok:" ascii wide
        $ = "explorer.exe" ascii wide
        $ = "file list error:open path [%s] error." ascii wide
        $ = "is already exist!" ascii wide
        $ = "is not exist!" ascii wide
        $ = "not exe:" ascii wide
        $ = "open file error:" ascii wide
        $ = "read file error:" ascii wide
        $ = "set config items error." ascii wide
        $ = "set config ok." ascii wide

    condition:
        15 of them or ( for any i in (0..pe.number_of_sections-1) : (pe.sections[i].name==".cotx"))
}rule CreateMiniDump
{
    meta:
        id = "kMNDXhwJQURe8ehDOueqk"
        fingerprint = "b391a564b4730559271e11de0b80dce1562a9038c230a2be729a896913c7f6b5"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CreateMiniDump, tool to dump LSASS."
        category = "HACKTOOL"
        tool = "CREATEMINIDUMP"
        reference = "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass"


    strings:
        $ = "[+] Got lsass.exe PID:" ascii wide
        $ = "[+] lsass dumped successfully!" ascii wide
        $ = { 40 55 57 4? 81 ec e8 04 00 00 4? 8d ?? ?4 40 4? 8b fc b9 3a 01 00 00 b8 cc cc cc cc f3 ab 4? 
  8b 05 ?? ?? ?? ?? 4? 33 c5 4? 89 8? ?? ?? ?? ?? c7 4? ?? 00 00 00 00 4? c7 4? ?? 00 00 00 00 4? 
  c7 44 ?? ?? 00 00 00 00 c7 44 ?? ?? 80 00 00 00 c7 44 ?? ?? 02 00 00 00 45 33 c9 45 33 c0 ba 00 
  00 00 10 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 89 4? ?? 33 d2 b9 02 00 00 00 e8 ?? ?? ?? ?? 
  4? 89 4? ?? 4? 8d ?? 90 00 00 00 4? 8b f8 33 c0 b9 38 02 00 00 f3 aa c7 8? ?? ?? ?? ?? 38 02 00
  00 4? 8d 05 ?? ?? ?? ?? 4? 89 ?? ?? ?? ?? ?? 4? 8d ?? 90 00 00 00 4? 8b 4? ?? e8 ?? ?? ?? ?? 85 
  c0 74 ?? 4? 8d 15 ?? ?? ?? ?? 4? 8b ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 ?? 4? 8d ?? 90 00 
  00 00 4? 8b 4? ?? e8 ?? ?? ?? ?? 4? 8d ?? bc 00 00 00 4? 89 8? ?? ?? ?? ?? 8b 8? ?? ?? ?? ?? 89 4? ?? }

    condition:
        any of them
}rule CrunchyRoll
{
    meta:
        id = "6MWD1MRYK1S03fFM5QvlHP"
        fingerprint = "2e0d0a32f42c7c8b800c373a229af29185a2a8c59eb7067de4acc0bcda232f23"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malware used in CrunchyRoll website hack."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2017/11/crunchyroll-hack-delivers-malware.html"


    strings:
        $ = "C:\\Users\\Ben\\Desktop\\taiga-develop\\bin\\Debug\\Taiga.pdb" ascii wide
        $ = "c:\\users\\ben\\source\\repos\\svchost\\Release\\svchost.pdb" ascii wide

    condition:
        any of them
}rule CryLock
{
    meta:
        id = "2l4H1zr9CK35G8zGAmRQAk"
        fingerprint = "f3084da9bc523ee78f0a85e439326c2f4a348330bf228192ca07c543f5fb04ed"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CryLock aka Cryakl ransomware."
        category = "MALWARE"
        malware = "CRYLOCK"
        malware_type = "RANSOMWARE"

    strings:
        $ = "///END ENCRYPT ONLY EXTENATIONS" ascii wide
        $ = "///END UNENCRYPT EXTENATIONS" ascii wide
        $ = "///END COMMANDS LIST" ascii wide
        $ = "///END PROCESSES KILL LIST" ascii wide
        $ = "///END SERVICES STOP LIST" ascii wide
        $ = "///END PROCESSES WHITE LIST" ascii wide
        $ = "///END UNENCRYPT FILES LIST" ascii wide
        $ = "///END UNENCRYPT FOLDERS LIST" ascii wide
        $ = "{ENCRYPTENDED}" ascii wide
        $ = "{ENCRYPTSTART}" ascii wide

    condition:
        2 of them
}rule Darkside
{
    meta:
        id = "5qjcs58k9iHd3EU3xv66sV"
        fingerprint = "57bc5c7353c8c518e057456b2317e1dbf59ee17ce69cd336f1bacaf627e9efd5"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Darkside ransomware."
        category = "MALWARE"
        malware = "DARKSIDE"
        malware_type = "RANSOMWARE"

    strings:
        $ = "darkside_readme.txt" ascii wide
        $ = "[ Welcome to DarkSide ]" ascii wide
        $ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
        $ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

    condition:
        any of them
}rule DearCry
{
    meta:
        id = "6wHCvbraYF2t1m7FWnjepd"
        fingerprint = "ce3c2631969e462acd01b9dc26fd03985076add51f8478e76aca93f260a020d8"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies DearCry ransomware."
        category = "MALWARE"
        malware = "DEARCRY"
        malware_type = "RANSOMWARE"
        reference = "https://twitter.com/MsftSecIntel/status/1370236539427459076"


    strings:
        $pdb = "C:\\Users\\john\\Documents\\Visual Studio 2008\\Projects\\EncryptFile -svcV2\\Release\\EncryptFile.exe.pdb" ascii wide
        $key = {4D 49 49 42 43 41 4B 43 41 51 45 41 79 4C 42 43 6C 7A 39 68 73 46 47 52 66 39 66 6B 33 7A 30 7A 6D 59 32 72 7A 32 4A 31 
    71 71 47 66 56 34 38 44 53 6A 50 56 34 6C 63 77 6E 68 43 69 34 2F 35 2B 0A 43 36 55 73 41 68 6B 2F 64 49 34 2F 35 48 77 62 66 5A 
    42 41 69 4D 79 53 58 4E 42 33 44 78 56 42 32 68 4F 72 6A 44 6A 49 65 56 41 6B 46 6A 51 67 5A 31 39 42 2B 4B 51 46 57 6B 53 6F 31 
    75 62 65 0A 56 64 48 6A 77 64 76 37 34 65 76 45 2F 75 72 39 4C 76 39 48 4D 2B 38 39 69 5A 64 7A 45 70 56 50 4F 2B 41 6A 4F 54 74 
    73 51 67 46 4E 74 6D 56 65 63 43 32 76 6D 77 39 6D 36 30 64 67 79 52 2F 31 0A 43 4A 51 53 67 36 4D 6F 62 6C 6F 32 4E 56 46 35 30 
    41 4B 33 63 49 47 32 2F 6C 56 68 38 32 65 62 67 65 64 58 73 62 56 4A 70 6A 56 4D 63 30 33 61 54 50 57 56 34 73 4E 57 6A 54 4F 33 
    6F 2B 61 58 0A 36 5A 2B 56 47 56 4C 6A 75 76 63 70 66 4C 44 5A 62 33 74 59 70 70 6B 71 5A 7A 41 48 66 72 43 74 37 6C 56 30 71 4F
    34 37 46 56 38 73 46 43 6C 74 75 6F 4E 69 4E 47 4B 69 50 30 38 34 4B 49 37 62 0A 33 58 45 4A 65 70 62 53 4A 42 33 55 57 34 6F 34 
    43 34 7A 48 46 72 71 6D 64 79 4F 6F 55 6C 6E 71 63 51 49 42 41 77 3D 3D}

    condition:
        any of them
}import "hash"
import "pe"

rule DefenderControl
{
    meta:
        id = "5wrFItxbjAcaTcQm9RW9IR"
        fingerprint = "0afa43f0e67bfa81406319e6e4f3ab71e2fe63476a1b7cc06660a68369155cbb"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Defender Control, used by attackers to disable Windows Defender."
        category = "MALWARE"
        malware = "DEFENDERCONTROL"
        reference = "https://www.sordum.org/9480/defender-control-v1-8/"


    strings:
        $ = "www.sordum.org" ascii wide
        $ = "dControl.exe" ascii wide

    condition:
        all of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="ff620e5c0a0bdcc11c3b416936bc661d"))
}rule Ekans
{
    meta:
        id = "6Kzy2bA2Zj7kvpXriuZ14m"
        fingerprint = "396b915c02a14aa809060946c9294f487a5107ab37ebefb6d5cde07de4113d43"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "EKANS"
        malware_type = "RANSOMWARE"
        actor_type = "APT"
        actor = "SNAKE"
        mitre_group = "TURLA"
        mitre_att = "S0605"

    strings:
        $ = "already encrypted!" ascii wide
        $ = "cant kill process %v : %v" ascii wide
        $ = "could not access service: %v" ascii wide
        $ = "could not retrieve service status: %v" ascii wide
        $ = "could not send control=%d: %v" ascii wide
        $ = "error encrypting %v : %v" ascii wide
        $ = "faild to get process list" ascii wide
        $ = "priority files: %v" ascii wide
        $ = "priorityFiles: %v" ascii wide
        $ = "pub: %v" ascii wide
        $ = "root: %v" ascii wide
        $ = "There can be only one" ascii wide
        $ = "timeout waiting for service to go to state=%d" ascii wide
        $ = "Toatal files: %v" ascii wide
        $ = "total lengt: %v" ascii wide
        $ = "worker %s started job %s" ascii wide

    condition:
        3 of them
}rule EnigmaStub
{
    meta:
        id = "nqfVjSZe90wUTGsVBo1SU"
        fingerprint = "7cc425b53393fbe7b1f4ad16d1fcb37f941199ff12341c74103c4cda14dd5e2c"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Enigma packer stub."
        category = "MALWARE"

    strings:
        $ = "Enigma anti-emulators plugin - GetProcAddress" ascii wide
        $ = "Enigma anti-debugger plugin - CheckRemoteDebuggerPresent" ascii wide
        $ = "Enigma anti-debugger plugin - IsDebuggerPresent" ascii wide
        $ = "Enigma Sandboxie Detect plugin" ascii wide
        $ = "Enigma_Plugin_Description" ascii wide
        $ = "Enigma_Plugin_About" ascii wide
        $ = "Enigma_Plugin_OnFinal" ascii wide
        $ = "EnigmaProtector" ascii wide
        $ = "Enigma_Plugin_OnInit" ascii wide

    condition:
        any of them
}rule Fusion
{
    meta:
        id = "5zeDUSWAX6101brsHGmiNB"
        fingerprint = "a1e5d90fc057d3d32754d241df9b1847eaad9e67e4b54368c28ee179a796944e"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Fusion ransomware, Go variant of Nemty/Nefilim."
        category = "MALWARE"
        malware = "FUSION"
        malware_type = "RANSOMWARE"

    strings:
        $s1 = "main.getdrives" ascii wide
        $s2 = "main.SaveNote" ascii wide
        $s3 = "main.FileSearch" ascii wide
        $s4 = "main.BytesToPublicKey" ascii wide
        $s5 = "main.GenerateRandomBytes" ascii wide
        $x1 = /Fa[i1]led to fi.Close/ ascii wide
        $x2 = /Fa[i1]led to fi2.Close/ ascii wide
        $x3 = /Fa[i1]led to get stat/ ascii wide
        $x4 = /Fa[i1]led to os.OpenFile/ ascii wide
        $pdb1 = "C:/OpenServer/domains/build/aes.go" ascii wide
        $pdb2 = "C:/Users/eugene/Desktop/test go/test.go" ascii wide
        $pdb3 = "C:/Users/eugene/Desktop/web/src/aes_" ascii wide

    condition:
        4 of ($s*) or 3 of ($x*) or any of ($pdb*)
}rule Ganelp
{
    meta:
        id = "5F6Z2reWdIRSLeXi6gf4RQ"
        fingerprint = "500d37e54fb6ba61cdfa9345db18e452d13288a8a42f24e1a55f3d24fbcf5bd0"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ganelp, a worm that also spreads via USB."
        category = "MALWARE"
        malware = "GANELP"
        malware_type = "WORM"
        

    strings:
        $ = "regardez cette photo :D %s" ascii wide
        $ = "to fotografiu :D %s" ascii wide
        $ = "vejte se na mou fotku :D %s" ascii wide
        $ = "bekijk deze foto :D %s" ascii wide
        $ = "spojrzec na to zdjecie :D %s" ascii wide
        $ = "bu resmi bakmak :D %s" ascii wide
        $ = "dette bildet :D %s" ascii wide
        $ = "seen this?? :D %s" ascii wide
        $ = "guardare quest'immagine :D %s" ascii wide
        $ = "denna bild :D %s" ascii wide
        $ = "olhar para esta foto :D %s" ascii wide
        $ = "uita-te la aceasta fotografie :D %s" ascii wide
        $ = "pogledaj to slike :D %s" ascii wide
        $ = "poglej to fotografijo :D %s" ascii wide
        $ = "dette billede :D %s" ascii wide

    condition:
        3 of them
}rule Generic_Phishing_PDF
{
    meta:
        id = "6iE0XEqqhVGNED6Z8xIMr1"
        fingerprint = "f3f31ec9651ee41552d41dbd6650899d7a33beea46ed1c3329c3bbd023fe128e"
        version = "1.0"
        creation_date = "2019-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies generic phishing PDFs."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2019/03/analysing-massive-office-365-phishing.html"


    strings:
        $pdf = {25504446}
        $s1 = "<xmp:CreatorTool>RAD PDF</xmp:CreatorTool>"
        $s2 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"DynaPDF"

    condition:
        $pdf at 0 and all of ($s*)
}import "pe"

rule Gmer
{
    meta:
        id = "8rI4CpbchoNUbZrro3sSW"
        fingerprint = "c8f734a69a66e320dba787e7a0d522c5db3566cd53b8ffcf855317996b8ec063"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Gmer, sometimes used by attackers to disable security software."
        category = "MALWARE"
        reference = "http://www.gmer.net/"


    strings:
        $ = "GMER %s - %s" ascii wide
        $ = "IDI_GMER" ascii wide fullword
        $ = "E:\\projects\\cpp\\gmer\\Release\\gmer.pdb" ascii wide

    condition:
        any of them
}import "pe"

rule Gmer_Driver
{
    meta:
        id = "47o6RMYvn1Hb14eggdrcHy"
        fingerprint = "7cc773597ea063add205ee1bce0ccce287d6f548ecb317923e83078a7018ed77"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Gmer's driver, sometimes used by attackers to disable security software."
        category = "MALWARE"
        reference = "http://www.gmer.net/"


    strings:
        $ = "e:\\projects\\cpp\\gmer\\driver64\\objfre_wlh_amd64\\amd64\\gmer64.pdb" ascii wide
        $ = "GMER Driver http://www.gmer.net" ascii wide

    condition:
        any of them or pe.version_info["OriginalFilename"] contains "gmer64.sys" or pe.version_info["InternalName"] contains "gmer64.sys"
}rule Hidden
{
    meta:
        id = "568PgDjhUwg620xlbE6vMk"
        fingerprint = "0fc71baad34741d864ec596e89fc873a01974d7ab6bea912d572c2bd2ae2e0da"
        version = "1.0"
        creation_date = "2021-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Hidden Windows driver, used by malware such as PurpleFox."
        category = "MALWARE"
        reference = "https://github.com/JKornev/hidden"


    strings:
        $ = "Hid_State" ascii wide
        $ = "Hid_StealthMode" ascii wide
        $ = "Hid_HideFsDirs" ascii wide
        $ = "Hid_HideFsFiles" ascii wide
        $ = "Hid_HideRegKeys" ascii wide
        $ = "Hid_HideRegValues" ascii wide
        $ = "Hid_IgnoredImages" ascii wide
        $ = "Hid_ProtectedImages" ascii wide
        $ = "Hid_HideImages" ascii wide

    condition:
        5 of them
}import "pe"

rule HiddenVNC
{
    meta:
        id = "15zXm5IVJkjh5ERo8y3PsR"
        fingerprint = "4910c9889e5940a74cb40eab4738c519c045a4ffa48fbb69c175e65421e86563"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies HiddenVNC, which can start remote sessions."
        category = "MALWARE"
        mitre_att = "T1021.005"

    strings:
        $ = "#hvnc" ascii wide
        $ = "VNC is starting your browser..." ascii wide
        $ = "HvncAction" ascii wide
        $ = "HvncCommunication" ascii wide
        $ = "hvncDesktop" ascii wide

    condition:
        2 of them or (pe.exports("VncStartServer") and pe.exports("VncStopServer"))
}rule IcedID_init_loader
{
    meta:
        id = "1GXBmGKG0zu5DhEKiZK0Kx"
        fingerprint = "b86460e97101c23cf11ff9fb43f6fcdce444fcfa301b1308c2f4d6aa2f01986a"
        version = "1.0"
        creation_date = "2021-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID (stage 1 and 2, initial loaders)."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"

    strings:
        $s1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" ascii wide
        $s2 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii wide
        $s3 = "/image/?id=%0.2X%0.8X%0.8X%s" ascii wide
        $x1 = "; _gat=" ascii wide
        $x2 = "; _ga=" ascii wide
        $x3 = "; _u=" ascii wide
        $x4 = "; __io=" ascii wide
        $x5 = "; _gid=" ascii wide
        $x6 = "Cookie: __gads=" ascii wide

    condition:
        2 of ($s*) or 3 of ($x*)
}

rule IcedID_core_loader
{
    meta:
        id = "682uTswieW7dk3i644FZ9F"
        fingerprint = "ffcfe3a1d5f0aad41892faf41c986a9601596d14f43985708f9bf4eb7d63a6b9"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID core loader."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"

    strings:
        $code = { 4? 33 d2 4? 85 f6 0f 84 ?? ?? ?? ?? 4? 83 fe 04 0f 
    82 ?? ?? ?? ?? 4? 83 c6 fc 4? 89 74 ?? ?? 4? 85 db 75 ?? 4? 
    85 f6 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 8b c8 4? 8d 46 
    01 8d 53 08 ff 15 ?? ?? ?? ?? 4? 89 44 ?? ?? 4? 8b d8 4? 85 
    c0 0f 84 ?? ?? ?? ?? 4? 8b b? ?? ?? ?? ?? 4? ba 01 00 00 00 }

    condition:
        $code
}rule IEuser_author_doc
{
    meta:
        id = "6KWw23emrB9UUOTTLuFIe9"
        fingerprint = "08cd3ae7218fba3334965f671c82ffcda47ffe510545d7859ef66e79619a1cbe"
        version = "1.0"
        creation_date = "2020-12-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Word documents created with the default user on IE11 test VMs, more likely to be suspicious."
        category = "MALWARE"
        reference = "https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/"


    strings:
        $doc = {D0 CF 11 E0}
        $ieuser = {49 00 45 00 55 00 73 00 65 00 72}

    condition:
        $doc at 0 and $ieuser
}rule IISRaid
{
    meta:
        id = "40tj9tn6FNrr4xE042IPIm"
        fingerprint = "521b0798e25a620534f8e04c8fd62fd42c90ea5b785968806cb7538986dedac6"
        version = "1.0"
        creation_date = "2021-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IISRaid."
        category = "MALWARE"
        malware = "IISRAID"
        malware_type = "BACKDOOR"
        reference = "https://github.com/0x09AL/IIS-Raid"


    strings:
        $pdb1 = "\\IIS-Raid-master\\" ascii wide
        $pdb2 = "\\IIS-Backdoor.pdb" ascii wide
        $s1 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
        $s2 = "C:\\Windows\\Temp\\creds.db" ascii wide
        $s3 = "CHttpModule::" ascii wide
        $s4 = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii wide

    condition:
        any of ($pdb*) or 3 of ($s*)
}rule Impacket
{
    meta:
        id = "4slxMFaVQR9nCS6mQxIQj"
        fingerprint = "3c84db45525bc8981b832617b35c0b81193827313b23c7fede0b00badc3670f4"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Impacket, a collection of Python classes for working with network protocols."
        category = "TOOL"
        tool = "IMPACKET"
        mitre_att = "S0357"
        reference = "https://github.com/SecureAuthCorp/impacket"


    strings:
        $ = "impacket.crypto" ascii wide
        $ = "impacket.dcerpc" ascii wide
        $ = "impacket.examples" ascii wide
        $ = "impacket.hresult_errors" ascii wide
        $ = "impacket.krb5" ascii wide
        $ = "impacket.nmb" ascii wide
        $ = "impacket.nt_errors" ascii wide
        $ = "impacket.ntlm" ascii wide
        $ = "impacket.smb" ascii wide
        $ = "impacket.smb3" ascii wide
        $ = "impacket.smb3structs" ascii wide
        $ = "impacket.smbconnection" ascii wide
        $ = "impacket.spnego" ascii wide
        $ = "impacket.structure" ascii wide
        $ = "impacket.system_errors" ascii wide
        $ = "impacket.uuid" ascii wide
        $ = "impacket.version" ascii wide
        $ = "impacket.winregistry" ascii wide

    condition:
        any of them
}rule ISO_exec
{
    meta:
        id = "2QhuTkbDSP1KGwZGeesrla"
        fingerprint = "27b4636deff9f19acfbbdc00cf198904d3eb630896514fb168a3dc5256abd7b4"
        version = "1.0"
        first_imported = "2022-07-29"
        last_modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in ISO files, seen in malware such as Bumblebee."
        category = "MALWARE"

strings:
       $ = "\\System32\\cmd.exe" ascii wide nocase
       $ = "\\System32\\rundll32.exe" ascii wide nocase
       $ = "OSTA Compressed Unicode" ascii wide
       $ = "UDF Image Creator" ascii wide

condition:
       uint16(0) != 0x5a4d and 3 of them
}
rule JSSLoader
{
    meta:
        id = "4kX6atSwDdjKnsiSNAVeZ2"
        fingerprint = "6c73b4052e8493cd64cae3794c3ebb92cb95f64dd5224326b1ca45aecd7cb6da"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies FIN7's JSSLoader."
        category = "MALWARE"
        malware = "JSSLOADER"
        malware_type = "LOADER"
        mitre_att = "S0648"

    strings:
        $s1 = "host" ascii wide fullword
        $s2 = "domain" ascii wide fullword
        $s3 = "user" ascii wide fullword
        $s4 = "processes" ascii wide fullword
        $s5 = "name" ascii wide fullword
        $s6 = "pid" ascii wide fullword
        $s7 = "desktop_file_list" ascii wide fullword
        $s8 = "file" ascii wide fullword
        $s9 = "size" ascii wide fullword
        $s10 = "adinfo" ascii wide fullword
        $s11 = "no_ad" ascii wide fullword
        $s12 = "adinformation" ascii wide fullword
        $s13 = "part_of_domain" ascii wide fullword
        $s14 = "pc_domain" ascii wide fullword
        $s15 = "pc_dns_host_name" ascii wide fullword
        $s16 = "pc_model" ascii wide fullword
        $x1 = "/?id=" ascii wide
        $x2 = "failed start exe" ascii wide
        $x3 = "Sending timer request failed, error code" ascii wide
        $x4 = "Internet connection failed, error code" ascii wide
        $x5 = "Sending initial request failed, error code" ascii wide

    condition:
        14 of ($s*) or 3 of ($x*)
}rule Jupyter
{
    meta:
        id = "5yGlzHFZQ1qvusLOwAt8UQ"
        fingerprint = "0c7ba0956c611a1e56ce972b4362f7f0f56bd2bd61ce78bee4adeb0a69e548c4"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Jupyter aka SolarMarker, backdoor."
        category = "MALWARE"
        malware = "SOLARMARKER"
        malware_type = "BACKDOOR"

    strings:
        $ = "var __addr__=" ascii wide
        $ = "var __hwid__=" ascii wide
        $ = "var __xkey__=" ascii wide
        $ = "solarmarker.dat" ascii wide

    condition:
        3 of them
}rule KeyBase
{
    meta:
        id = "5cV9wZM0UzNuIyF7OK1Tpk"
        fingerprint = "d959211abb79a5b0e4e1e2e8c30bc6963876dcbe929e9099085dd2cc75dce730"
        version = "1.0"
        creation_date = "2019-02-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies KeyBase aka Kibex."
        category = "MALWARE"
        malware = "KEYBASE"
        hash = "cafe2d12fb9252925fbd1acb9b7648d6"

    strings:
        $s1 = " End:]" ascii wide
        $s2 = "Keystrokes typed:" ascii wide
        $s3 = "Machine Time:" ascii wide
        $s4 = "Text:" ascii wide
        $s5 = "Time:" ascii wide
        $s6 = "Window title:" ascii wide
        $x1 = "&application=" ascii wide
        $x2 = "&clipboardtext=" ascii wide
        $x3 = "&keystrokestyped=" ascii wide
        $x4 = "&link=" ascii wide
        $x5 = "&username=" ascii wide
        $x6 = "&windowtitle=" ascii wide
        $x7 = "=drowssap&" ascii wide
        $x8 = "=emitenihcam&" ascii wide

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or 6 of ($x*) or (3 of ($s*) and 3 of ($x*)))
}rule KPortScan
{
    meta:
        id = "3ywZWmdGN5mlc73cUnzre"
        fingerprint = "ee8fb9b2387f2fe406f89b99b46f8f1b3855df23e09908c67b53c13532160915"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies KPortScan, port scanner."
        category = "MALWARE"
        malware_type = "SCANNER"

    strings:
        $s1 = "KPortScan 3.0" ascii wide
        $s2 = "KPortScan3.exe" ascii wide
        $x1 = "Count of goods:" ascii wide
        $x2 = "Current range:" ascii wide
        $x3 = "IP ranges list is clear" ascii wide
        $x4 = "ip,port,state" ascii wide
        $x5 = "on_loadFinished(QNetworkReply*)" ascii wide
        $x6 = "on_scanDiapFinished()" ascii wide
        $x7 = "on_scanFinished()" ascii wide
        $x8 = "scanDiapFinished()" ascii wide
        $x9 = "scanFinished()" ascii wide
        $x10 = "with port" ascii wide
        $x11 = "without port" ascii wide

    condition:
        any of ($s*) or 3 of ($x*)
}rule LaZagne
{
    meta:
        id = "3DeKZTrvc1lTK9vNaoj7LG"
        fingerprint = "81ef321369e94e5cb5bbf735ab7db8c6aafc1fc7564c76d53b3f0e0adb9e5c81"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LaZagne, credentials recovery project."
        category = "TOOL"
        tool = "LAZAGNE"
        mitre_att = "S0349"
        reference = "https://github.com/AlessandroZ/LaZagne"


    strings:
        $ = "[!] Specify a directory, not a file !" ascii wide
        $ = "lazagne.config" ascii wide
        $ = "lazagne.softwares" ascii wide
        $ = "blazagne.exe.manifest" ascii wide
        $ = "slaZagne" ascii wide fullword

    condition:
        any of them
}rule LNKR_JS_a
{
    meta:
        id = "2ptjcpBqa9yDFmKpt0AW5C"
        fingerprint = "371d54a77d89c53acc9135095361279f9ecd479ec403f6a14bc393ec0032901b"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "AMZN_SEARCH" ascii wide
        $ = "BANNER_LOAD" ascii wide
        $ = "CB_FSI_ANSWER" ascii wide
        $ = "CB_FSI_BLIND_NO_URL" ascii wide
        $ = "CB_FSI_BREAK" ascii wide
        $ = "CB_FSI_DISPLAY" ascii wide
        $ = "CB_FSI_DO_BLIND" ascii wide
        $ = "CB_FSI_ERROR_EXCEPTION" ascii wide
        $ = "CB_FSI_ERROR_PARSERESULT" ascii wide
        $ = "CB_FSI_ERROR_TIMEOUT" ascii wide
        $ = "CB_FSI_ERR_INVRELINDEX" ascii wide
        $ = "CB_FSI_ERR_INV_BLIND_POS" ascii wide
        $ = "CB_FSI_FUSEARCH" ascii wide
        $ = "CB_FSI_FUSEARCH_ORGANIC" ascii wide
        $ = "CB_FSI_INJECT_EMPTY" ascii wide
        $ = "CB_FSI_OPEN" ascii wide
        $ = "CB_FSI_OPTOUTED" ascii wide
        $ = "CB_FSI_OPTOUT_DO" ascii wide
        $ = "CB_FSI_ORGANIC_RESULT" ascii wide
        $ = "CB_FSI_ORGANIC_SHOW" ascii wide
        $ = "CB_FSI_ORGREDIR" ascii wide
        $ = "CB_FSI_SKIP" ascii wide
        $ = "MNTZ_INJECT" ascii wide
        $ = "MNTZ_LOADED" ascii wide
        $ = "OPTOUT_SHOW" ascii wide
        $ = "PROMO_ANLZ" ascii wide
        $ = "URL_IGNOREDOMAIN" ascii wide
        $ = "URL_STATICFILE" ascii wide

    condition:
        5 of them
}

rule LNKR_JS_b
{
    meta:
        id = "FooEUkiF1qekRyatQeewJ"
        fingerprint = "bcc81d81472d21d4fdbd10f7713c77e7246b07644abf5c2a0c8e26bf3a2d2865"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "StartAll ok" ascii wide
        $ = "dexscriptid" ascii wide
        $ = "dexscriptpopup" ascii wide
        $ = "rid=LAUNCHED" ascii wide

    condition:
        3 of them
}

rule LNKR_JS_c
{
    meta:
        id = "1QAyO1czEHnDRAk825ZUFn"
        fingerprint = "9c839a66b2212d9ae94cd4ccd0150ff1c9c34d3fa797f015afa742407a7f4d4b"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "var affid" ascii wide
        $ = "var alsotry_enabled" ascii wide
        $ = "var boot_time" ascii wide
        $ = "var checkinc" ascii wide
        $ = "var dom" ascii wide
        $ = "var fsgroup" ascii wide
        $ = "var gcheckrunning" ascii wide
        $ = "var kodom" ascii wide
        $ = "var last_keywords" ascii wide
        $ = "var trkid" ascii wide
        $ = "var uid" ascii wide
        $ = "var wcleared" ascii wide

    condition:
        3 of them
}

rule LNKR_JS_d
{
    meta:
        id = "ixfWYGMOBADN6j1c4HrnP"
        fingerprint = "ea7abac4ced554a26930c025a84bc5188eb195f2b3488628063f0be35c937a59"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "adTrack" ascii wide
        $ = "addFSBeacon" ascii wide
        $ = "addYBeacon" ascii wide
        $ = "algopopunder" ascii wide
        $ = "applyAdDesign" ascii wide
        $ = "applyGoogleDesign" ascii wide
        $ = "deleteElement" ascii wide
        $ = "fixmargin" ascii wide
        $ = "galgpop" ascii wide
        $ = "getCurrentKw" ascii wide
        $ = "getGoogleListing" ascii wide
        $ = "getParameterByName" ascii wide
        $ = "getXDomainRequest" ascii wide
        $ = "googlecheck" ascii wide
        $ = "hasGoogleListing" ascii wide
        $ = "insertAfter" ascii wide
        $ = "insertNext" ascii wide
        $ = "insertinto" ascii wide
        $ = "isGoogleNewDesign" ascii wide
        $ = "moreReq" ascii wide
        $ = "openInNewTab" ascii wide
        $ = "pagesurf" ascii wide
        $ = "replaceRel" ascii wide
        $ = "sendData" ascii wide
        $ = "sizeinc" ascii wide
        $ = "streamAds" ascii wide
        $ = "urlcleanup" ascii wide

    condition:
        10 of them
}import "math"

private rule isLNK
{
    meta:
        id = "1XKPrHhGUVGxZ9ZtveVhF9"
        fingerprint = "399c994f697568637efb30910b80f5ae7bedd42bf1cf4188cb74610e46cb23a8"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Private rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
        category = "INFO"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }

    condition:
        $lnk at 0
}

rule PS_in_LNK
{
    meta:
        id = "5PjnTrwMNGYdZahLd6yrPa"
        fingerprint = "d89b0413d59b57e5177261530ed1fb60f0f6078951a928caf11b2db1c2ec5109"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerShell artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".ps1" ascii wide nocase
        $ = "powershell" ascii wide nocase
        $ = "invoke" ascii wide nocase
        $ = "[Convert]" ascii wide nocase
        $ = "FromBase" ascii wide nocase
        $ = "-exec" ascii wide nocase
        $ = "-nop" ascii wide nocase
        $ = "-noni" ascii wide nocase
        $ = "-w hidden" ascii wide nocase
        $ = "-enc" ascii wide nocase
        $ = "-decode" ascii wide nocase
        $ = "bypass" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Script_in_LNK
{
    meta:
        id = "24OwxeALdNyMpIq2oeeatL"
        fingerprint = "bed7b00cdd2966629d9492097d357b729212d6d90251b9f1319634af05f40fdc"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies scripting artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "javascript" ascii wide nocase
        $ = "jscript" ascii wide nocase
        $ = "vbscript" ascii wide nocase
        $ = "wscript" ascii wide nocase
        $ = "cscript" ascii wide nocase
        $ = ".js" ascii wide nocase
        $ = ".vb" ascii wide nocase
        $ = ".wsc" ascii wide nocase
        $ = ".wsh" ascii wide nocase
        $ = ".wsf" ascii wide nocase
        $ = ".sct" ascii wide nocase
        $ = ".cmd" ascii wide nocase
        $ = ".hta" ascii wide nocase
        $ = ".bat" ascii wide nocase
        $ = "ActiveXObject" ascii wide nocase
        $ = "eval" ascii wide nocase

    condition:
        isLNK and any of them
}

rule EXE_in_LNK
{
    meta:
        id = "3SSZmnnXU0l4qoc9wubdhN"
        fingerprint = "f169fab39da34f827cdff5ee022374f7c1cc0b171da9c2bb718d8fee9657d7a3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".exe" ascii wide nocase
        $ = ".dll" ascii wide nocase
        $ = ".scr" ascii wide nocase
        $ = ".pif" ascii wide nocase
        $ = "This program" ascii wide nocase
        $ = "TVqQAA" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Archive_in_LNK
{
    meta:
        id = "2ku4ClpAScswD86dAiYijX"
        fingerprint = "91946edcd14021c70c3dc4e1898b346f671095e87715df73fa4db3a70074b918"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies archive (compressed) files in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".7z" ascii wide nocase
        $ = ".zip" ascii wide nocase
        $ = ".cab" ascii wide nocase
        $ = ".iso" ascii wide nocase
        $ = ".rar" ascii wide nocase
        $ = ".bz2" ascii wide nocase
        $ = ".tar" ascii wide nocase
        $ = ".lzh" ascii wide nocase
        $ = ".dat" ascii wide nocase
        $ = "WinRAR\\Rar.exe" ascii wide nocase
        $ = "expand" ascii wide nocase
        $ = "makecab" ascii wide nocase
        $ = "UEsDBA" ascii wide nocase
        $ = "TVNDRg" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Execution_in_LNK
{
    meta:
        id = "77XnooZUMUCCdEuppmQ0My"
        fingerprint = "cf4910d057f099ef2d2b6fc80739a41e3594c500e6b4eca0fc8f64e48f6dcefb"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "cmd.exe" ascii wide nocase
        $ = "/c echo" ascii wide nocase
        $ = "/c start" ascii wide nocase
        $ = "/c set" ascii wide nocase
        $ = "%COMSPEC%" ascii wide nocase
        $ = "rundll32.exe" ascii wide nocase
        $ = "regsvr32.exe" ascii wide nocase
        $ = "Assembly.Load" ascii wide nocase
        $ = "[Reflection.Assembly]::Load" ascii wide nocase
        $ = "process call" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Compilation_in_LNK
{
    meta:
        id = "6MFIj6PnQMhnF21XItMr42"
        fingerprint = "58d09c8cd94f0d8616d16195bd7fa0335657dd87235e204d49979785cdd8007e"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compilation artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "vbc.exe" ascii wide nocase
        $ = "csc.exe" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Download_in_LNK
{
    meta:
        id = "4oUWRvBhzXFLJVKxasN6Cd"
        fingerprint = "9b95b86b48df38523f1e382483c7a7fd96da1a0244b5ebdd2327eaf904afd117"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies download artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "bitsadmin" ascii wide nocase
        $ = "certutil" ascii wide nocase
        $ = "ServerXMLHTTP" ascii wide nocase
        $ = "http" ascii wide nocase
        $ = "ftp" ascii wide nocase
        $ = ".url" ascii wide nocase

    condition:
        isLNK and any of them
}

rule MSOffice_in_LNK
{
    meta:
        id = "5wsZnuCXdcxZ1DbLHFC4pX"
        fingerprint = "ac2e453ed19a4f30f17a1c7ff4c8dfcd00b2c2fc53c7ab05d32f5e6a91326da1"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Office artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "winword" ascii wide nocase
        $ = "excel" ascii wide nocase
        $ = "powerpnt" ascii wide nocase
        $ = ".rtf" ascii wide nocase
        $ = ".doc" ascii wide nocase
        $ = ".dot" ascii wide nocase
        $ = ".xls" ascii wide nocase
        $ = ".xla" ascii wide nocase
        $ = ".csv" ascii wide nocase
        $ = ".ppt" ascii wide nocase
        $ = ".pps" ascii wide nocase
        $ = ".xml" ascii wide nocase

    condition:
        isLNK and any of them
}

rule PDF_in_LNK
{
    meta:
        id = "7U50CQK54jXHGYojYg4wKe"
        fingerprint = "5640fd2e7a31adf7f080658f07084d5e7b9dd89d2e58c49ffd7fe50f16bfcaa2"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Acrobat artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".pdf" ascii wide nocase
        $ = "%PDF" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Flash_in_LNK
{
    meta:
        id = "2onsBjSNyoLIP4WLOVgS56"
        fingerprint = "4d47314dce183d422d05f220835a28920f06caf8fa54c62e2427938ca68627f3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Flash artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".swf" ascii wide nocase
        $ = ".fws" ascii wide nocase

    condition:
        isLNK and any of them
}

rule SMB_in_LNK
{
    meta:
        id = "5jhrc6f5nuBGClq72MwVw5"
        fingerprint = "530336ad2ab3fadb07e5f6517b0ac435a0e0b88a47226e5bbf43b5bcc9a79176"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        category = "INFO"

    strings:
        $ = "\\c$\\" ascii wide nocase

    condition:
        isLNK and any of them
}


rule Long_RelativePath_LNK
{
    meta:
        id = "2ogEIXl8u2qUbIgxTmruYX"
        fingerprint = "4b822248bade98d0528ab13549797c225784d7f953fe9c14d178c9d530fb3e55"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with a long relative path. Might be used in an attempt to hide the path."
        category = "INFO"

    strings:
        $ = "..\\..\\..\\..\\" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Large_filesize_LNK
{
    meta:
        id = "2N6jerukOyU2qFFtcMtnWt"
        fingerprint = "a8168e65294bfc0b9ffca544891b818b37feb5b780ab357efbb56638c6578242"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file larger than 100KB. Most goodware LNK files are smaller than 100KB."
        category = "INFO"

    condition:
        isLNK and filesize >100KB
}

rule High_Entropy_LNK
{
    meta:
        id = "6Dqf8gBGF21dKt03BJOXbQ"
        fingerprint = "d0b5bdad04d5894cd1136ec57bd6410180923e9267edb932c8dca6ef3a23722d"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with equal or higher entropy than 6.5. Most goodware LNK files have a low entropy, lower than 6."
        category = "INFO"

    condition:
        isLNK and math.entropy(0, filesize )>=6.5
}

rule CDN_in_LNK
{
    meta:
        id = "q22YL1ZnAbHqVNq9Iz1Bn"
        fingerprint = "81b8267b7286f4baa02c533c7a4f17e17b38859a81cc0186b1b47c89498b6a0e"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CDN (Content Delivery Network) domain in shortcut (LNK) file."
        category = "INFO"

    strings:
        $ = "cdn." ascii wide nocase
        $ = "githubusercontent" ascii wide nocase
        $ = "googleusercontent" ascii wide nocase
        $ = "cloudfront" ascii wide nocase
        $ = "amazonaws" ascii wide nocase
        $ = "akamai" ascii wide nocase
        $ = "cdn77" ascii wide nocase
        $ = "discordapp" ascii wide nocase

    condition:
        isLNK and any of them
}
rule MalScript_Tricks
{
    meta:
        id = "3xg5wneq3ZntsMg61ltshS"
        fingerprint = "6c78cbc1250afb36970d87d8ee2fe8409f57c9d34251d6e3908454e6643f92e3"
        version = "1.0"
        creation_date = "2020-12-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies tricks often seen in malicious scripts such as moving the window off-screen or resizing it to zero."
        category = "MALWARE"

    strings:
        $s1 = "window.moveTo -" ascii wide nocase
        $s2 = "window.resizeTo 0" ascii wide nocase
        $x1 = "window.moveTo(-" ascii wide nocase
        $x2 = "window.resizeTo(" ascii wide nocase

    condition:
        ( all of ($s*) or all of ($x*)) and filesize <50KB
}rule Maze
{
    meta:
        id = "4sTbmIEE40nSKc9rOEz4po"
        fingerprint = "305df5e5f0a4d5660dff22073881e65ff25528895abf26308ecd06dd70a97ec2"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Maze ransomware in memory or unpacked."
        category = "MALWARE"
        malware = "MAZE"
        malware_type = "RANSOMWARE"
        mitre_att = "S0449"

    strings:
        $ = "Enc: %s" ascii wide
        $ = "Encrypting whole system" ascii wide
        $ = "Encrypting specified folder in --path parameter..." ascii wide
        $ = "!Finished in %d ms!" ascii wide
        $ = "--logging" ascii wide
        $ = "--nomutex" ascii wide
        $ = "--noshares" ascii wide
        $ = "--path" ascii wide
        $ = "Logging enabled | Maze" ascii wide
        $ = "NO SHARES | " ascii wide
        $ = "NO MUTEX | " ascii wide
        $ = "Encrypting:" ascii wide
        $ = "You need to buy decryptor in order to restore the files." ascii wide
        $ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
        $ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
        $ = "DECRYPT-FILES.txt" ascii wide fullword

    condition:
        5 of them
}rule MiniTor
{
    meta:
        id = "2kfngTvJBttBM67MLYYyil"
        fingerprint = "035c4826400ab70d1fa44a6452e1c738851994d3215e8d944f33b9aa2d409fe0"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies MiniTor implementation as seen in SystemBC and Parallax RAT."
        category = "MALWARE"
        malware_type = "RAT"
        reference = "https://news.sophos.com/en-us/2020/12/16/systembc/"


    strings:
        $code1 = {55 8b ec 81 c4 f0 fd ff ff 51 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 6a 0f 8d ?? 00 fe ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d ?? 0f fe ff ff 50 6a 14 ff 
        7? ?? e8 ?? ?? ?? ?? 8d ?? fc fd ff ff 50 8d ?? 00 fe ff ff 50 ff 7? ?? ff 7? ?? e8 ?? ?? 
        ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b b? ?? ?? ?? ?? 89 8? ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? 
        ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? 
        ?? ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b f7 83 c6 1e 8d ?? 00 fe ff ff c6}
        $code2 = {55 8b ec 81 c4 78 f8 ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 68 00 00 00 f0 6a 0d 68 ?? ?? ?? ?? 6a 00 8d ?? fc 50 e8 ?? ?? ?? ?? 6a 00 6a 00 8d 05 
        ?? ?? ?? ?? 5? 8d ?? f8 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 
        ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f4 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f0 50 68 ?? ?? ?? ?? 
        e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 20 8d 05 ?? ?? ?? ?? 5? 8d 
        05 ?? ?? ?? ?? 5? ff 7? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50}

    condition:
        any of them
}rule Monero_Compromise
{
    meta:
        id = "2oIDqilozjDoCoilh0uEV2"
        fingerprint = "749f8aa9e70217387a3491e3e050d37e85fee65e50ae476e58a1dc77198fc017"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compromised Monero binaries."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2019/11/monero-project-compromised.html"


    strings:
        $ = "ZN10cryptonote13simple_wallet9send_seedERKN4epee15wipeable_stringE" ascii wide
        $ = "ZN10cryptonote13simple_wallet10send_to_ccENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_i" ascii wide
        $ = "node.xmrsupport.co" ascii wide
        $ = "node.hashmonero.com" ascii wide

    condition:
        any of them
}rule NLBrute
{
    meta:
        id = "6b1itE1MIciily5r3hEAlg"
        fingerprint = "b303f9469c58c3c8417b5825ba949adf7032192a9f29cc8346b90636dd2ca7b5"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies NLBrute, an RDP brute-forcing tool."
        category = "HACKTOOL"

    strings:
        $ = "SERVER:PORT@DOMAIN\\USER;PASSWORD" ascii wide

    condition:
        any of them
}rule oAuth_Phishing_PDF
{
    meta:
        id = "789YmThaTvLDaE1V2Oqx7q"
        fingerprint = "c367bca866de0b066e291b4e45216cbb68cc23297b002a29ca3c8d640a7db78e"
        version = "1.0"
        creation_date = "2022-01-01"
        first_imported = "2022-02-03"
        last_modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies potential phishing PDFs that target oAuth."
        category = "MALWARE"
        reference = "https://twitter.com/ffforward/status/1484127442679836676"

    strings:
        $pdf = {25504446} //%PDF
        $s1 = "/URI (https://login.microsoftonline.com/common/oauth2/" ascii wide nocase
        $s2 = "/URI (https://login.microsoftonline.com/consumers/oauth2" ascii wide nocase
        $s3 = "/URI (https://accounts.google.com/o/oauth2" ascii wide nocase

    condition:
        $pdf at 0 and any of ($s*)
}
rule OfflRouter
{
    meta:
        id = "2I5ccrcSBA9kdy7i0OPcb7"
        fingerprint = "6b633ac8b42943fd5868a2632518c3c30104010478c0fc42ee3613e3581b876e"
        version = "1.0"
        creation_date = "2022-01-01"
        first_imported = "2022-01-24"
        last_modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies OfflRouter, malware which spreads to Office documents and removable drives."
        category = "MALWARE"
        reference = "https://www.csirt.gov.sk/wp-content/uploads/2021/08/analysis_offlrouter.pdf"

    strings:
		/*
		Dim num As Long = 0L
		Dim num2 As Long = CLng((Bytes.Length - 1))
		For num3 As Long = num To num2
		Bytes(CInt(num3)) = (Bytes(CInt(num3)) Xor CByte(((num3 + CLng(Bytes.Length) + 1L) Mod &H100L)))
		*/
	    $ = { 16 6A 02 50 8E B7 17 59 6A 0B 0A 2B 22 02 50 06 69 02 50 06 69 91 06 02 50 8E B7 6A 58 17 6A 58 20 00 01 00 00 6A 5D D2 61 9C 06 17 6A 58 0A 06 07 }

    condition:
        all of them
}
rule OLEfile_in_CAD_FAS_LSP
{
    meta:
        id = "3Ie7cdUdqnv46f0qtY5cfU"
        fingerprint = "178edb2c2d85cc62b6c89ef84044df6631889869b56a5cbb6162ba7fa62939a3"
        version = "1.0"
        creation_date = "2019-12-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies OLE files embedded in AutoCAD and related Autodesk files, quite uncommon and potentially malicious."
        category = "MALWARE"
        reference = "https://blog.didierstevens.com/2019/12/16/analyzing-dwg-files-with-vba-macros/"


    strings:
        $acad = {41 43 31}
        $fas = {0D 0A 20 46 41 53 34 2D 46 49 4C 45 20 3B 20 44 6F 20 6E 6F 74 20 63 68 61 6E 67 65 20 69 74 21}
        $lsp1 = "lspfilelist"
        $lsp2 = "setq"
        $lsp3 = ".lsp"
        $lsp4 = "acad.mnl"
        $ole = {D0 CF 11 E0}

    condition:
        ($acad at 0 and $ole) or ($fas at 0 and $ole) or (( all of ($lsp*)) and $ole)
}rule OneNote_BuildPath
{
    meta:
        id = "6lPn0V5wZyc2iuEz13uKAZ"
        fingerprint = "f8ed9e3cdd5411e2bda7495c8b00b8e69e8f495db97cf542f6a1f3b790bef7a5"
        version = "1.0"
        first_imported = "2023-02-02"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malicious OneNote file by build path."
        category = "MALWARE"

strings:
	//Z:\build\one\attachment.hta
	$path_0 = {5a003a005c006200750069006c0064005c006f006e0065005c006100740074006100630068006d0065006e0074002e00680074006100}
	//Z:\builder\O P E N.wsf
	$path_1 = {5a003a005c006200750069006c006400650072005c004f00200050002000450020004e002e00770073006600}

condition:
	filesize <200KB and any of them
}
rule Parallax
{
    meta:
        id = "7AHV77y7ZoCjGyFbljjWV6"
        fingerprint = "3ae9c820e411829619984c5e5311e8940248a771cfde3f22d2789ccb3c099be8"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Parallax RAT."
        category = "MALWARE"
        malware = "PARALLAX"
        malware_type = "RAT"

    strings:
        $ = ".DeleteFile(Wscript.ScriptFullName)" ascii wide
        $ = ".DeleteFolder" ascii wide fullword
        $ = ".FileExists" ascii wide fullword
        $ = "= CreateObject" ascii wide fullword
        $ = "Clipboard Start" ascii wide fullword
        $ = "UN.vbs" ascii wide fullword
        $ = "[Alt +" ascii wide fullword
        $ = "[Clipboard End]" ascii wide fullword
        $ = "[Ctrl +" ascii wide fullword

    condition:
        3 of them
}import "pe"

rule PowerTool
{
    meta:
        id = "1xsVS7M8rwYUf81xA2UjIE"
        fingerprint = "0244bd12a172270bedd0165ea5fd95ee4176e46a0fb501e0888281927fbbea4b"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerTool, sometimes used by attackers to disable security software."
        category = "MALWARE"
        malware = "POWERTOOL"
        reference = "https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml"


    strings:
        $ = "C:\\dev\\pt64_en\\Release\\PowerTool.pdb" ascii wide
        $ = "Detection may be stuck, First confirm whether the device hijack in [Disk trace]" ascii wide
        $ = "SuspiciousDevice Error reading MBR(Kernel Mode) !" ascii wide
        $ = "Modify kill process Bug." ascii wide
        $ = "Chage language nedd to restart PowerTool" ascii wide
        $ = ".?AVCPowerToolApp@@" ascii wide
        $ = ".?AVCPowerToolDlg@@" ascii wide

    condition:
        any of them
}rule Prometei_Main
{
    meta:
        id = "1tLZbijQrm8kKt1oDLFgVx"
        fingerprint = "59c25b325938e0ade0f4437005d25e48444f5a79a91f7836490e826e588c2e66"
        version = "1.0"
        first_imported = "2023-03-24"
        last_modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Prometei botnet main modules."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"

  strings:
    $ = "prometeicmd" ascii wide fullword
    $ = "/cgi-bin/prometei.cgi" ascii wide

condition:
    any of them
}

rule Prometei_PDB
{
    meta:
        id = "6RxW5l6ySxPS5K2HD7b6wX"
        fingerprint = "c9342fa61b7e5e711016dab5e6360e836726cf622feed88da92b7aaa4dd79f4a"
        version = "1.0"
        first_imported = "2023-03-24"
        last_modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies debug paths for Prometei botnet."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"

strings:
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\walker\\/ ascii wide
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\prometei\\/ ascii wide
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\misc\\/ ascii wide

condition:
    any of them
}

import "dotnet"
rule Prometei_Dotnet
{
    meta:
        id = "2tFf2nXDFh5zWf8bp0syJ8"
        fingerprint = "efcf00534325da6e45ee56e96fdc7e8063cb20706eef6765cc220a4335220a61"
        version = "1.0"
        first_imported = "2023-03-24"
        last_modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies dotnet modules used by Prometei botnet, specifically BlueKeep and NetHelper."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"

strings:
    $crypt = {13 30 05 00 DB 00 00 00 0? 00 00 11 20 00 01 00 00 8D ?? 00 00 01 13 05 20 00 01 00 00 8D ?? 00 00 01 13 06 03 8E 69 8D ?? 00 00 01 13 07 16 0B 2B 14 11 05 07 02 07 02 8E 69 5D 91 9E 11 06 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 E4 16 16 0B 0C 2B 2A 08 11 06 07 94 58 11 05 07 94 58 20 00 01 00 00 5D 0C 11 06 07 94 13 04 11 06 07 11 06 08 94 9E 11 06 08 11 04 9E 07 17 58 0B 07 20 00 01 00 00 32 CE 16 16 0B 16 0C 0A 2B 50 06 17 58 0A 06 20 00 01 00 00 5D 0A 08 11 06 06 94 58 0C 08 20 00 01 00 00 5D 0C 11 06 06 94 13 04 11 06 06 11 06 08 94 9E 11 06 08 11 04 9E 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5D 94 0D 11 07 07 03 07 91 09 61 D2 9C 07 17 58 0B 07 03 8E 69 32 AA 11 07 2A}

condition:
    $crypt or dotnet.typelib == "daee89b2-0055-46ce-bbab-abb621d6bef1" or dotnet.typelib == "6e74992f-648e-471f-9879-70f57b73ec8d"
}

rule Prometei_Spreader
{
    meta:
        id = "EH3oMrAkcLfDxYgZXKd8o"
        fingerprint = "4eb71a189ef2651539d70f8202474394972a9dc0ad3218260c8af8a48e3ccdc5"
        version = "1.0"
        first_imported = "2023-03-24"
        last_modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SSH spreader used by Prometei botnet, specifically windrlver."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"

strings:
    $code = {8a 01 41 84 c0 75 ?? 2b ce 8d 04 13 2b cb 03 c7 2b cf 51 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 83 c4 0c 33 db 8d 9b 00 00 00 00}

condition:
    $code
}
rule PurpleFox_a
{
    meta:
        id = "oxM5h0sJv3kfrf6E6rDMZ"
        fingerprint = "fef41f58521abd9a60ad6c35f7b0fe466e132f0e592bea1439b9f42799a50eb4"
        version = "1.0"
        creation_date = "2021-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet."
        category = "MALWARE"
        malware = "PURPLEFOX"
        malware_type = "BOT"

    strings:
        $movetmp = { 4? 8d 4d 38 4? 8b 95 88 01 00 00 4? 8d 05 1f 01 00 00 e8 9a c8 fd ff 4? 8b 4d 38 e8 51 cc fd ff 4? 89 c1 4? 8d 55 48 e8 55 07 fe ff 4? 89 c3 4? 83 fb ff 74 74 8b 45 48 83 e0 10 83 f8 10 74 50 4? 8d 4d 30 4? 8d 55 74 4? c7 c0 04 01 00 00 4? 33 c9 e8 9a c6 fd ff 4? 8d 4d 40 4? 8b 95 88 01 00 00 4? 8b 45 30 e8 46 c8 fd ff 4? 8b 4d 40 e8 fd cb fd ff 4? 89 c1 4? 33 d2 e8 c2 09 fe ff 4? 8b 4d 40 e8 e9 cb fd ff 4? 89 c1 e8 a1 06 fe ff 4? 89 d9 4? 8d 55 48 e8 f5 06 fe ff 85 c0 75 95 4? 89 d9 e8 19 3d fe ff  }

    condition:
        all of them
}

rule PurpleFox_b
{
    meta:
        id = "5dC5laJvjwww0AfMejPBAT"
        fingerprint = "84ade7b1f157b33b53d04b84689ad6ea4309abe40c2dad360825eb2f0e6a373b"
        version = "1.0"
        creation_date = "2021-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet."
        category = "MALWARE"

    strings:
        $ = /dump_[A-Z0-9]{8}/ ascii wide
        $ = "cscdll.dll" ascii wide
        $ = "sens.dll" ascii wide

    condition:
        all of them
}

rule PurpleFox_c
{
    meta:
        id = "5ImXAdrniKP1eF4xcQJpmC"
        fingerprint = "078423ceb734b361b95537288f5d8b96d6c5d91b10fa5728c253131b35f0c201"
        version = "1.0"
        creation_date = "2021-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet."
        category = "MALWARE"

    strings:
        $ = "UpProxyRandom" ascii wide
        $ = "SetServiceName" ascii wide
        $ = "DrvServiceName" ascii wide
        $ = "DriverOpenName" ascii wide
        $ = "DirLogFilePath" ascii wide
        $ = "RunPeShellPath" ascii wide
        $ = "DriverFileName" ascii wide

    condition:
        all of them
}

rule PurpleFox_Dropper
{
    meta:
        id = "27j3DK8uiYjKigXCaoPUEK"
        fingerprint = "53c2af74e917254858409ea37d32e250656aa741800516020bdfff37732a3f51"
        version = "1.0"
        creation_date = "2021-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet, dropper CAB or MSI package."
        category = "MALWARE"
        malware_type = "DROPPER"

    strings:
        $doc = {D0 CF 11 E0}
        $cab = {4D 53 43 46}
        $s1 = "sysupdate.log" ascii wide
        $s2 = "winupdate32.log" ascii wide
        $s3 = "winupdate64.log" ascii wide

    condition:
        ($doc at 0 and all of ($s*)) or ($cab at 0 and all of ($s*))
}
import "hash"
import "pe"

rule PyInstaller
{
    meta:
        id = "6Pyq57uDDAEHbltmbp7xRT"
        fingerprint = "ae849936b19be3eb491d658026b252c2f72dcb3c07c6bddecb7f72ad74903eee"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable converted using PyInstaller."
        category = "MALWARE"

    strings:
        $ = "pyi-windows-manifest-filename" ascii wide
        $ = "pyi-runtime-tmpdir" ascii wide
        $ = "PyInstaller: " ascii wide

    condition:
        uint16(0)==0x5a4d and any of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="20d36c0a435caad0ae75d3e5f474650c"))
}rule Pysa
{
    meta:
        id = "240byxdCwyzaTk3xgjzbEa"
        fingerprint = "7f8819e9f76b9c97e90cd5da7ea788c9bb1eb135d8e1cb8974d6f17ecf51b3c3"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Pysa aka Mespinoza ransomware."
        category = "MALWARE"
        malware = "PYSA"
        malware_type = "RANSOMWARE"
        mitre_att = "S0583"

    strings:
        $code = { 8a 0? 41 84 c0 75 ?? 2b ce 8b 35 ?? ?? ?? ?? 8d 41 01 50 5? 6a 07 6a 00 68 ?? ?? ?? 
    ?? ff 7? ?? ff d? 6a 05 68 ?? ?? ?? ?? 6a 07 6a 00 68 ?? ?? ?? ?? ff 7? ?? ff d? ff 7? ?? ff 
    15 ?? ?? ?? ?? 8b 4? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d c3 }
        $s1 = "n.pysa" ascii wide fullword
        $s2 = "%s\\Readme.README" ascii wide
        $s3 = "Every byte on any types of your devices was encrypted." ascii wide

    condition:
        $code or 2 of ($s*)
}rule RagnarLocker
{
    meta:
        id = "5066KiqBNrcicJGfWPfDx5"
        fingerprint = "fd403ea38a9c6c269ff7b72dea1525010f44253a41e72bf3fce55fa4623245a3"
        version = "1.0"
        creation_date = "2020-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RagnarLocker ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "RAGNAR LOCKER"
        malware_type = "RANSOMWARE"
        mitre_att = "S0481"

    strings:
        $ = "RAGNRPW" ascii wide
        $ = "---END KEY R_R---" ascii wide
        $ = "---BEGIN KEY R_R---" ascii wide

    condition:
        any of them
}import "hash"
import "pe"

rule Rclone
{
    meta:
        id = "23v8f9e4P2BkrMqYH5mcBN"
        fingerprint = "4f7ec548a91c112a2d05f3b8449f934e2e4eaf7bf6dab032a26ac3511799a7bf"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Rclone, sometimes used by attackers to exfiltrate data."
        category = "MALWARE"
        malware_type = "INFOSTEALER"
        reference = "https://rclone.org/"


    strings:
        $ = "github.com/rclone/" ascii wide
        $ = "The Rclone Authors" ascii wide
        $ = "It copies the drive file with ID given to the path" ascii wide
        $ = "rc vfs/forget file=hello file2=goodbye dir=home/junk" ascii wide
        $ = "rc to flush the whole directory cache" ascii wide

    condition:
        any of them or for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="fc675e36c61c8b9d0b956bd05695cdda")
}rule RDPWrap
{
    meta:
        id = "5t73wrjJYkVLaE3Mn4a6sp"
        fingerprint = "f16d06fc8f81dcae5727af12a84956fc7b3c2aab120d6f4eaac097f7452e71d4"
        version = "1.0"
        creation_date = "2020-05-01"
        first_imported = "2021-12-30"
        last_modified = "2022-11-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RDP Wrapper, sometimes used by attackers to maintain persistence."
        category = "MALWARE"
        reference = "https://github.com/stascorp/rdpwrap"


    strings:
        $ = "rdpwrap.dll" ascii wide
        $ = "rdpwrap.ini" ascii wide
        $ = "RDP Wrapper" ascii wide
        $ = "RDPWInst" ascii wide
        $ = "Stas'M Corp." ascii wide
        $ = "stascorp" ascii wide

    condition:
        2 of them
}
rule RedLine_a
{
    meta:
        id = "4Eeg9my5Llk67wiTDuBhLS"
        fingerprint = "8ba3c33d3affea6488b4fc056ad672922e243c790f16695bcf27c6dfab4ec611"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"
        malware = "REDLINE"
        malware = "INFOSTEALER"

    strings:
        $ = "Account" ascii wide
        $ = "AllWalletsRule" ascii wide
        $ = "ArmoryRule" ascii wide
        $ = "AtomicRule" ascii wide
        $ = "Autofill" ascii wide
        $ = "BrowserExtensionsRule" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chrome" ascii wide
        $ = "CoinomiRule" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "CryptoHelper" ascii wide
        $ = "CryptoProvider" ascii wide
        $ = "DataBaseConnection" ascii wide
        $ = "DesktopMessangerRule" ascii wide
        $ = "DiscordRule" ascii wide
        $ = "DisplayHelper" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "ElectrumRule" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "EthRule" ascii wide
        $ = "ExodusRule" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScannerRule" ascii wide
        $ = "FileZilla" ascii wide
        $ = "GameLauncherRule" ascii wide
        $ = "Gecko" ascii wide
        $ = "GeoHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "GuardaRule" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IpSb" ascii wide
        $ = "IRemoteEndpoint" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "JaxxRule" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPNRule" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "Program" ascii wide
        $ = "ProgramMain" ascii wide
        $ = "ProtonVPNRule" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "RecoursiveFileGrabber" ascii wide
        $ = "ResultFactory" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScannedBrowser" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "ScanResult" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "XMRRule" ascii wide

    condition:
        45 of them
}

rule RedLine_b
{
    meta:
        id = "6Ds02SHJ9xqDC5ehVb5PEZ"
        fingerprint = "5ecb15004061205cdea7bcbb6f28455b6801d82395506fd43769d591476c539e"
        version = "1.0"
        creation_date = "2021-10-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"

    strings:
        $ = "Account" ascii wide
        $ = "AllWallets" ascii wide
        $ = "Autofill" ascii wide
        $ = "Browser" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chr_0_M_e" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "ConfigReader" ascii wide
        $ = "DesktopMessanger" ascii wide
        $ = "Discord" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScanning" ascii wide
        $ = "FileSearcher" ascii wide
        $ = "FileZilla" ascii wide
        $ = "FullInfoSender" ascii wide
        $ = "GameLauncher" ascii wide
        $ = "GdiHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IContract" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "IdentitySenderBase" ascii wide
        $ = "LocalState" ascii wide
        $ = "LocatorAPI" ascii wide
        $ = "NativeHelper" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPN" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "ParsSt" ascii wide
        $ = "PartsSender" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScanResult" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "SenderFactory" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "WalletConfig" ascii wide

    condition:
        45 of them
}
import "dotnet"

rule RedLine_Campaign_June2021
{
    meta:
        id = "6obnDftS8HPC8ATVxov3ol"
        fingerprint = "4f389cf9f0343eb0e526c25f0beea9a0b284e96029dc064e85557ae2fe8bdf9d"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer's June 2021 campaign."
        category = "MALWARE"
        malware = "REDLINE"
        malware_type = "INFOSTEALER"
        reference = "https://bartblaze.blogspot.com/2021/06/digital-artists-targeted-in-redline.html"


    condition:
        dotnet.guids[0]=="a862cb90-79c7-41a9-847b-4ce4276feaeb" or dotnet.guids[0]=="a955bdf8-f5ac-4383-8f5d-a4111125a40e" or dotnet.guids[0]=="018ca516-2128-434a-b7c6-8f9a75dfc06e" or dotnet.guids[0]=="829c9056-6c93-42c2-a9c8-19822ccac0a4" or dotnet.guids[0]=="e1a702b0-dee1-463a-86d3-e6a9aa86348e" or dotnet.guids[0]=="6152d28b-1775-47e6-902f-8bdc9e2cb7ca" or dotnet.guids[0]=="111ab36c-09ad-4a3e-92b3-a01076ce68e0" or dotnet.guids[0]=="ea7dfb6d-f951-48e6-9e25-41c31080fd42" or dotnet.guids[0]=="34bca13d-abb5-49ce-8333-052ec690e01e" or dotnet.guids[0]=="1422b4dd-c4c1-4885-b204-200e83267597" or dotnet.guids[0]=="d0570d65-3998-4954-ab42-13b122f7dde5"
}rule Responder
{
    meta:
        id = "542DKcb5v7CRu4SFgfHBAj"
        fingerprint = "5ae4386a4f020726581f7d0082f15bf6f412c7e5db79904663a2f2d4ac5a1a58"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Responder, an LLMNR, NBT-NS and MDNS poisoner."
        category = "HACKTOOL"
        tool = "RESPONDER"
        mitre_att = "S0174"
        reference = "https://github.com/lgandx/Responder"


    strings:
        $ = "[*] [LLMNR]" ascii wide
        $ = "[*] [NBT-NS]" ascii wide
        $ = "[*] [MDNS]" ascii wide
        $ = "[FINGER] OS Version" ascii wide
        $ = "[FINGER] Client Version" ascii wide
        $ = "serve_thread_udp_broadcast" ascii wide
        $ = "serve_thread_tcp_auth" ascii wide
        $ = "serve_NBTNS_poisoner" ascii wide
        $ = "serve_MDNS_poisoner" ascii wide
        $ = "serve_LLMNR_poisoner" ascii wide
        $ = "poisoners.LLMNR " ascii wide
        $ = "poisoners.NBTNS" ascii wide
        $ = "poisoners.MDNS" ascii wide

    condition:
        any of them
}rule REvil_Dropper
{
    meta:
        id = "77UKzYTt79Q5WVUpRQgOiK"
        fingerprint = "0b55e00e07c49e450fa643b5c8f4c1c03697c0f15d8f95c709e9b1a3cf2340ed"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies the dropper used by REvil in the Kaseya supply chain attack."
        category = "MALWARE"
        malware = "REVIL"
        malware_type = "RANSOMWARE"
        mitre_att = "S0496"
        reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
        hash = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"

    strings:
        $ = { 55 8b ec 56 8b 35 24 d0 40 00 68 04 1c 41 00 6a 65 6a 00 ff 
     d6 85 c0 0f 84 98 00 00 00 50 6a 00 ff 15 20 d0 40 00 85 c0 0f 84 
      87 00 00 00 50 ff 15 18 d0 40 00 68 14 1c 41 00 6a 66 6a 00 a3 a0 
      43 41 00 ff d6 85 c0 74 6c 50 33 f6 56 ff 15 20 d0 40 00 85 c0 74 
      5e 50 ff 15 18 d0 40 00 68 24 1c 41 00 ba 88 55 0c 00 a3 a4 43 41 
      00 8b c8 e8 9a fe ff ff 8b 0d a0 43 41 00 ba d0 56 00 00 c7 04 ?4 
      38 1c 41 00 e8 83 fe ff ff c7 04 ?4 ec 43 41 00 68 a8 43 41 00 56 
      56 68 30 02 00 00 56 56 56 ff 75 10 c7 05 a8 43 41 00 44 00 00 00 
      50 ff 15 28 d0 40 00 }
        $ = { 55 8b ec 83 ec 08 e8 55 ff ff ff 85 c0 75 04 33 c0 eb 67 68 
    98 27 41 00 68 68 b7 0c 00 a1 f4 32 41 00 50 e8 58 fe ff ff 83 c4 
    0c 89 45 f8 68 80 27 41 00 68 d0 56 00 00 8b 0d f0 32 41 00 51 e8 
    3c fe ff ff 83 c4 0c 89 45 fc c7 05 f8 32 41 00 44 00 00 00 68 3c 
    33 41 00 68 f8 32 41 00 6a 00 6a 00 6a 08 6a 00 6a 00 6a 00 8b 55 
    10 52 8b 45 fc 50 ff 15 28 c0 40 00 33 c0 }

    condition:
        any of them
}rule RoyalRoad_RTF
{
    meta:
        id = "p1XW7z3B1sdN89zXF7Nel"
        fingerprint = "52be45a991322fa96f4e806cf6fa7a77886f63799c1f67723484bc3796363a4e"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RoyalRoad RTF, used by multiple Chinese APT groups."
        category = "MALWARE"
        malware = "ROYALROAD"        
        malware_type = "EXPLOITKIT"
        reference = "https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html"


    strings:
        $rtf = "{\\rt"
        $RR1 = "5C746D705C382E74" ascii wide nocase
        $RR2 = "5C417070446174615C4C6F63616C5C54656D705C382E74" ascii wide nocase

    condition:
        $rtf at 0 and any of ($RR*)
}rule SaintBot
{
    meta:
        id = "5zQ5DvA1lpgHKfGgGgFvvp"
        fingerprint = "f8ed9e3cdd5411e2bda7495c8b00b8e69e8f495db97cf542f6a1f3b790bef7a5"
        version = "1.0"
        creation_date = "2022-07-29"
        first_imported = "2022-07-29"
        last_modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Saint Bot malware downloader."
        category = "MALWARE"
        malware = "SAINTBOT"
        malware_type = "DOWNLOADER"

    strings:
        $ = "de:regsvr32" ascii wide
        $ = "de:LoadMemory" ascii wide
        $ = "de:LL" ascii wide
        $ = "/gate.php" ascii wide

    condition:
        all of them
}
rule Satan_Mutexes
{
    meta:
        id = "4jKp8prwufSCRdyuJPHFX3"
        fingerprint = "4c325bd0f020e626a484338a3f88cbcf6c14bfa10201e52c2fde8c7c331988fb"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Satan ransomware (and its variants) by mutex."
        category = "MALWARE"
        malware = "SATAN"
        malware_type = "RANSOMWARE"
        reference = "https://bartblaze.blogspot.com/2020/01/satan-ransomware-rebrands-as-5ss5c.html"


    strings:
        $ = "SATANAPP" ascii wide
        $ = "SATAN_SCAN_APP" ascii wide
        $ = "STA__APP" ascii wide
        $ = "DBGERAPP" ascii wide
        $ = "DBG_CPP" ascii wide
        $ = "run_STT" ascii wide
        $ = "SSS_Scan" ascii wide
        $ = "SSSS_Scan" ascii wide
        $ = "5ss5c_CRYPT" ascii wide

    condition:
        any of them
}rule Sfile
{
    meta:
        id = "64arpb3yJ0mZxamCG9jIVs"
        fingerprint = "7a2be690f14a9ea61917c2c31b4d44186295de7d8a1342f081ed9507a8ac46b0"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Sfile aka Escal ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"

    strings:
        $pdb = "D:\\code\\ransomware_win\\bin\\ransomware.pdb" ascii wide
        $ = "%s SORTING time : %s" ascii wide
        $ = "%ws -> WorkModeDecryptFiles : %d of %d files decrypted +%d (%d MB)..." ascii wide
        $ = "%ws -> WorkModeEncryptFiles : %d of %d files encrypted +%d [bps : %d, size = %d MB] (%d skipped, ld = %d.%d.%d %d:%d:%d, lf = %ws)..." ascii wide
        $ = "%ws -> WorkModeEnded" ascii wide
        $ = "%ws -> WorkModeFindFiles : %d files / %d folders found (already (de?)crypted %d/%d) (lf = %ws)..." ascii wide
        $ = "%ws -> WorkModeSorting" ascii wide
        $ = "%ws ENCRYPTFILES count : %d (%d skipped), time : %s" ascii wide
        $ = "%ws FINDFILES RESULTS : dwDirectoriesCount = %d, dwFilesCount = %d MB = %d (FIND END)" ascii wide
        $ = "%ws FINDFILES time : %s" ascii wide
        $ = "DRIVE_FIXED : %ws" ascii wide
        $ = "EncryptDisk(%ws) DONE" ascii wide
        $ = "ScheduleRoutine() : gogogo" ascii wide
        $ = "ScheduleRoutine() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
        $ = "WARN! FileLength more then memory has %ws" ascii wide
        $ = "WaitForHours() : gogogo" ascii wide
        $ = "WaitForHours() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
        $ = "Your network has been penetrated." ascii wide
        $ = "--kill-susp" ascii wide
        $ = "--enable-shares" ascii wide

    condition:
        $pdb or 3 of them
}rule ShinnyShield
{
meta:
	id = "4kRs05vapnmQ15Bz1V4RDu"
	fingerprint = "efbf32d12e094c838e2375689bbafeadb7859529ba87aefb45ae0a76575faf1d"
	version = "1.0"
	first_imported = "2023-08-01"
	last_modified = "2023-08-01"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Worm that spreads via Call of Duty Modern Warfare 2, 2009 version."
	reference = "https://techcrunch.com/2023/07/27/hackers-are-infecting-call-of-duty-players-with-a-self-spreading-malware" 

strings:
    $msg_dbg1 = "Adding legitimate lobby to party list." ascii wide
    $msg_dbg2 = "Discarded QoS response from modded lobby." ascii wide
    $msg_dbg3 = "Handled join accept from " ascii wide
    $msg_dbg4 = "Handled join request from " ascii wide
    $msg_dbg5 = "Incorrect exe or mw2 version!" ascii wide
    $msg_dbg6 = "Locking the RCE to " ascii wide
    $msg_dbg7 = "Received packet from " ascii wide
    $msg_dbg8 = "Refusing to join blacklisted lobby." ascii wide
    $msg_dbg9 = "Unauthorized RCE attempt detected." ascii wide
    $msg_dbg10 = "Unknown or missing worm instruction." ascii wide
    $msg_dbg11 = "User was randomly selected to be a spreader in modded lobbies." ascii wide
    $msg_dbg12 = "User was selected to be a host/ignore modded lobbies/join unmodded lobbies only" ascii wide
    $msg_worm1 = "Worm deactivated by control server." ascii wide
    $msg_worm2 = "Worm failed to retrieve data from the control server." ascii wide
    $msg_worm3 = "Worm killed by control server." ascii wide
    $msg_worm4 = "Worm up to date." ascii wide
    $msg_worm5 = "wormStatus infected %s" ascii wide
    $msg_worm6 = "get cucked by shiny" ascii wide

    $pdb = "F:\\1337 Call Of Duty\\dxproxies\\DirectX-Wrappers\\Release\\dsound.pdb" ascii wide

    $exp = "joinParty 149 1 1 0 0 0 32 0 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"
    
condition:
    3 of ($msg_*) or $pdb or $exp
}
rule Specialist_Repack_Doc
{
    meta:
        id = "5kJT4oOJwT8lbgHDb9e8Cw"
        fingerprint = "0cc8378c4bca64dae2268f62576408b652014280adaeddfa9e02d3a91f26f1b9"
        version = "1.0"
        creation_date = "2022-01-01"
        first_imported = "2022-01-24"
        last_modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Office documents created by a cracked Office version, SPecialiST RePack."
        category = "MALWARE"
        reference = "https://twitter.com/malwrhunterteam/status/1483132689586831365"

    strings:
        $ = "SPecialiST RePack" ascii wide
        $ = {53 50 65 63 69 61 6C 69 53 54 20 52 65 50 61 63 6B}

    condition:
        any of them
}
rule SystemBC_Socks
{
    meta:
        id = "6zIY8rmud3SM6CWLPwxaky"
        fingerprint = "09472e26edd142cd68a602f1b6e31abbd4c8ec90c36d355a01692d44ef02a14f"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, Socks proxy version."
        category = "MALWARE"
        malware = "SYSTEMBC"
        malware_type = "RAT"

    strings:
        $code1 = { 68 10 27 00 00 e8 ?? ?? ?? ?? 8d ?? 72 fe ff ff 50 68 02 02 00 00 e8 ?? ?? 
    ?? ?? 85 c0 75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 6a ff 68 ?? ?? 
    ?? ?? e8 ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 e8 ?? ?? ?? ?? 89 8? ?? ?? ?? ?? ff b? ?? 
    ?? ?? ?? ff b? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 81 b? ?? ?? ?? ?? ?? ?? ?? ?? 
    75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? eb ?? }
        $code2 = { 55 8b ec 81 c4 d0 fe ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 
    ?? ?? ?? ?? 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 4? ?? 6a 04 ff 7? ?? 8d ?? fc 50 e8 
    ?? ?? ?? ?? c7 8? ?? ?? ?? ?? 01 00 00 00 6a 04 8d ?? d4 fe ff ff 50 6a 01 6a 06 ff 
    7? ?? e8 ?? ?? ?? ?? 8d ?? d8 fe ff ff 50 6a ff ff 7? ?? e8 ?? ?? ?? ?? 6a 02 8d ?? 
    d8 fe ff ff 50 e8 ?? ?? ?? ?? 89 4? ?? 8b 4? ?? 3d 00 00 01 00 76 ?? 50 e8 ?? ?? ?? ?? }

    condition:
        any of them
}

rule SystemBC_Config
{
    meta:
        id = "70WDDM1D5xtPBqsUdBiPTK"
        fingerprint = "8de029e2f4fc81742a3e04976a58360e403ce5737098c14e0a007c306a1e0f01"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, decrypted config."
        category = "MALWARE"
        malware_type = "RAT"

    strings:
        $ = "BEGINDATA" ascii wide fullword
        $ = "HOST1:" ascii wide fullword
        $ = "HOST2:" ascii wide fullword
        $ = "PORT1:" ascii wide fullword
        $ = "TOR:" ascii wide fullword
        $ = "-WindowStyle Hidden -ep bypass -file" ascii wide

    condition:
        3 of them
}rule Unk_BR_Banker
{
    meta:
        id = "5IYTPDXywF5zMWuDcnVYFz"
        fingerprint = "188bfe548c195449556fa093144b8bd7ed2eb6d506b1fd251ee6c131a34dc59b"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies an unknown Brazilian banking trojan."
        category = "MALWARE"
        malware_type = "BANKER"

    strings:
        $ = "<ALARME>" ascii wide
        $ = "<ALARME_G>" ascii wide
        $ = "<ALARME_R>" ascii wide
        $ = "<|LULUZDC|>" ascii wide
        $ = "<|LULUZLD|>" ascii wide
        $ = "<|LULUZLU|>" ascii wide
        $ = "<|LULUZPos|>" ascii wide
        $ = "<|LULUZRD|>" ascii wide
        $ = "<|LULUZRU|>" ascii wide
        $ = ">CRIAR_ALARME_AZUL<" ascii wide
        $ = ">ESCREVER_BOTAO_DIREITO<" ascii wide
        $ = ">REMOVER_ALARME_GRAY<" ascii wide
        $ = ">WIN_SETA_ACIMA<" ascii wide
        $ = ">WIN_SETA_BAIXO<" ascii wide
        $ = ">WIN_SETA_ESQUERDA<" ascii wide
        $ = "BOTAO_DIREITO" ascii wide

    condition:
        5 of them
}import "pe"

rule Unk_Crime_Downloader_1
{
    meta:
        id = "5T0oYPMEQOSKnlIWNqI5y"
        fingerprint = "826ce149c9b9f2aa04176213db1a8e8c8a57f0c2bcaeceb532a8282b80c31f7b"
        version = "1.0"
        creation_date = "2020-10-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Unknown downloader DLL, likely used by Emotet and/or TrickBot."
        category = "MALWARE"
        malware = "EMOTET"
        malware_type = "DOWNLOADER"
        mitre_att = "S0367"
        hash = "3d2ca7dc3d7c0aa120ed70632f9f0a15"

    strings:
        $ = "LDR.dll" ascii wide fullword
        $ = "URLDownloadToFileA" ascii wide

    condition:
        all of them or pe.imphash()=="4f8a708f1b809b780e4243486a40a465"
}rule Unk_DesktopLoader
{
    meta:
        id = "5XutaPgnKyd7zIb41Eqna1"
        fingerprint = "1c8def2957471e3fc4b17be9fd65466b23b8cf997f0df74fb6103f8421751a2e"
        version = "1.0"
        creation_date = "2021-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies implant that will decrypt and load shellcode from a blob file. Calling it DesktopLoader for now, based on the filename it seeks."
        category = "MALWARE"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"


    strings:
        $ = { 68 00 08 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 33 
    c9 85 c0 7e ?? ba 5c 00 00 00 8d 49 00 66 39 14 ?? ?? ?? ?? ?? 
    75 ?? 85 c9 74 ?? 49 48 85 c0 7f ?? eb ?? 33 c9 66 89 0c ?? ?? 
    ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 
    68 80 00 00 00 6a 03 6a 00 6a 02 68 00 00 00 80 68 ?? ?? ?? ?? 
    ff 15 ?? ?? ?? ?? 83 f8 ff 75 ?? 6a 00 ff 15 ?? ?? ?? ?? }

    condition:
        any of them
}rule VMProtectStub
{
    meta:
        id = "2mnOM2GhTL6NcFzr8Jt2RS"
        fingerprint = "60278c38aaf4a92a81cdda628e85dc2670f1e95665fcfbac87f40b225a4a28c2"
        version = "1.0"
        creation_date = "2020-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies VMProtect packer stub."
        category = "MALWARE"

    strings:
        $ = ".?AV?$VirtualAllocationManager@VRealAllocationStrategy@@@@" ascii wide
        $ = ".?AVEncryptedFastDllStream@@" ascii wide
        $ = ".?AVGetBlock_CC@HardwareID@@" ascii wide
        $ = ".?AVHookManager@@" ascii wide
        $ = ".?AVIDllStream@@" ascii wide
        $ = ".?AVIGetBlock@HardwareID@@" ascii wide
        $ = ".?AVIHookManager@@" ascii wide
        $ = ".?AVIUrlBuilderSource@@" ascii wide
        $ = ".?AVIVirtualAllocationManager@@" ascii wide
        $ = ".?AVMyActivationSource@@" ascii wide

    condition:
        2 of them
}rule Webshell_in_image
{
    meta:
        id = "6IgdjyQO28avrjCjsw4VWh"
        fingerprint = "459e953dedb3a743094868b6ba551e72c3640e3f4d2d2837913e4288e88f6eca"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies a webshell or backdoor in image files."
        category = "MALWARE"
        malware_type = "WEBSHELL"

    strings:
        $gif = {47 49 46 38 3? 61}
        $png = {89 50 4E 47 0D 0A 1A 0A}
        $jpeg = {FF D8 FF E0}
        $bmp = {42 4D}
        $s1 = "<%@ Page Language=" ascii wide
        $s2 = "<?php" ascii wide nocase
        $s3 = "eval(" ascii wide nocase
        $s4 = "<eval" ascii wide nocase
        $s5 = "<%eval" ascii wide nocase

    condition:
        ($gif at 0 and any of ($s*)) or ($png at 0 and any of ($s*)) or ($jpeg at 0 and any of ($s*)) or ($bmp at 0 and any of ($s*))
}rule WhiteBlack
{
    meta:
        id = "7TdI06IvZtnFNYtUZ7ZD4X"
        fingerprint = "4b5caed33ff2cb41dea4dbe77f84a536d91b92b5837c439a50ebfdcce28fd701"
        version = "1.0"
        creation_date = "2022-01-01"
        first_imported = "2022-02-03"
        last_modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WhiteBlack ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        malware = "WHITEBLACK"
        reference = "https://twitter.com/siri_urz/status/1377877204776976384"

    strings:
        //_Str2 = strcat(_Str2,".encrpt3d"); Encrypt block
		$ = { 55 57 56 53 4? 83 ec 28 31 db bd 00 01 00 00 89 cf 31 c9 ff 15 ?? ?? ?? ?? 89 c1 e8 ?? ?? ?? ?? 4? 63 cf e8 ?? ?? ?? ?? 4? 89 c6 39 df 7e ?? e8 ?? ?? ?? ?? 99 f7 fd 88 14 1e 4? ff c3 eb ?? 4? 89 f0 4? 83 c4 28 5b 5e 5f 5d c3 4? 55 4? 54 55 57 56 53 4? 83 ec 28 4? 8d 15 ?? ?? ?? ?? 31 f6 4? 8d 2d ?? ?? ?? ?? 4? 89 cd e8 ?? ?? ?? ?? b9 00 00 00 02 4? 89 c3 e8 ?? ?? ?? ?? 4? 89 c7 4? 89 d9 4? b8 00 00 00 02 ba 01 00 00 00 4? 89 f9 e8 ?? ?? ?? ?? 85 c0 4? 89 c4 74 ?? 81 fe ff ff ff 3f 7f ?? 4? 89 e0 4? 89 fa 4? 89 e? e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? 4? 01 e6 4? 63 c4 4? 89 f9 4? 89 d9 ba 01 00 00 00 e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? eb ?? 4? 89 f9 4? 89 ef e8 ?? ?? ?? ?? 4? 89 d9 e8 ?? ?? ?? ?? 31 c0 4? 83 c9 ff f2 ae 4? 89 ce 4? f7 d6 4? 89 f1 4? 83 c1 09 e8 ?? ?? ?? ?? 4? 89 ea 4? 89 c1 e8 ?? ?? ?? ?? 4? 8d 15 ?? ?? ?? ?? 4? 89 c1 e8 ?? ?? ?? ?? 4? 89 e9 4? 89 c2 4? 83 c4 28 }

    condition:
        any of them
}
rule WickrMe
{
    meta:
        id = "6yM5V73btyHP2BBFhj8cXv"
        fingerprint = "1c7f8412455ea211f7a1606f49151be31631c17f37a612fb3942aff075c7ddaa"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WickrMe (aka Hello) ransomware."
        category = "MALWARE"
        malware = "WICKRME"
        malware_type = "RANSOMWARE"
        reference = "https://www.trendmicro.com/en_ca/research/21/d/hello-ransomware-uses-updated-china-chopper-web-shell-sharepoint-vulnerability.html"


    strings:
        $ = "[+] Config Service..." ascii wide
        $ = "[+] Config Services Finished" ascii wide
        $ = "[+] Config Shadows Finished" ascii wide
        $ = "[+] Delete Backup Files..." ascii wide
        $ = "[+] Generate contact file {0} successfully" ascii wide
        $ = "[+] Generate contact file {0} failed! " ascii wide
        $ = "[+] Get Encrypt Files..." ascii wide
        $ = "[+] Starting..." ascii wide
        $ = "[-] No Admin Rights" ascii wide
        $ = "[-] Exit" ascii wide

    condition:
        4 of them
}rule Windows_Credentials_Editor
{
    meta:
        id = "3Q5yGnr66Sy8HikXBcYqKN"
        fingerprint = "2ba3672c391e1426f01f623538f85bc377eec8ff60eda61c1af70f191ab683a3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Windows Credentials Editor (WCE), post-exploitation tool."
        category = "HACKTOOL"
        tool = "WINDOWS CREDENTIAL EDITOR"
        mitre_att = "S0005"
        reference = "https://www.ampliasecurity.com/research/windows-credentials-editor/"


    strings:
        $ = "Windows Credentials Editor" ascii wide
        $ = "Can't enumerate logon sessions!" ascii wide
        $ = "Cannot get PID of LSASS.EXE!" ascii wide
        $ = "Error: cannot dump TGT" ascii wide
        $ = "Error: Cannot extract auxiliary DLL!" ascii wide
        $ = "Error: cannot generate LM Hash." ascii wide
        $ = "Error: cannot generate NT Hash." ascii wide
        $ = "Error: Cannot open LSASS.EXE!." ascii wide
        $ = "Error in cmdline!." ascii wide
        $ = "Forced Safe Mode Error: cannot read credentials using 'safe mode'." ascii wide
        $ = "Reading by injecting code! (less-safe mode)" ascii wide
        $ = "username is too long!." ascii wide
        $ = "Using WCE Windows Service.." ascii wide
        $ = "Using WCE Windows Service..." ascii wide
        $ = "Warning: I will not be able to extract the TGT session key" ascii wide
        $ = "WCEAddNTLMCredentials" ascii wide
        $ = "wceaux.dll" ascii wide fullword
        $ = "WCEGetNTLMCredentials" ascii wide
        $ = "wce_ccache" ascii wide fullword
        $ = "wce_krbtkts" ascii wide fullword

    condition:
        3 of them
}rule WinLock
{
    meta:
        id = "3MQTREUk3DgifGki8sa7hl"
        fingerprint = "6d659e5dc636a9535d07177776551ae3b32eae97b86e3e7dd01d74d0bbe33c82"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WinLock (aka Blocker) ransomware variants generically."
        category = "MALWARE"
        malware = "WINLOCK"
        malware_type = "RANSOMWARE"

    strings:
        $s1 = "twexx32.dll" ascii wide
        $s2 = "s?cmd=ul&id=%s" ascii wide
        $s3 = "card_ukash.png" ascii wide
        $s4 = "toneo_card.png" ascii wide
        $pdb = "C:\\Kuzja 1.4\\vir.vbp" ascii wide
        $x1 = "AntiWinLockerTray.exe" ascii wide
        $x2 = "Computer name:" ascii wide
        $x3 = "Current Date:" ascii wide
        $x4 = "Information about blocking" ascii wide
        $x5 = "Key Windows:" ascii wide
        $x6 = "Password attempts:" ascii wide
        $x7 = "Registered on:" ascii wide
        $x8 = "ServiceAntiWinLocker.exe" ascii wide
        $x9 = "Time of Operation system:" ascii wide
        $x10 = "To removing the system:" ascii wide

    condition:
        3 of ($s*) or $pdb or 5 of ($x*)
}rule XiaoBa
{
    meta:
        id = "7HQbk7TyDS3DhwWOktZe9t"
        fingerprint = "d41a019709801bbbc4284b27fd7f582ed1db624415cb28b88a7cdf5b0c3331b2"
        version = "1.0"
        creation_date = "2019-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies XiaoBa ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "XIAOBA"
        malware_type = "RANSOMWARE"

    strings:
        $ = "BY:TIANGE" ascii wide
        $ = "Your disk have a lock" ascii wide
        $ = "Please enter the unlock password" ascii wide
        $ = "Please input the unlock password" ascii wide
        $ = "I am very sorry that all your files have been encrypted" ascii wide

    condition:
        any of them
}rule Zeppelin
{
    meta:
        id = "RIttcGgKqwaotJyTgah7j"
        fingerprint = "a4da7defafa7f510df1c771e3d67bf5d99f3684a44f56d2b0e6f40f0a7fea84f"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Zeppelin ransomware and variants (Buran, Vega etc.)"
        category = "MALWARE"
        malware = "ZEPPELIN"
        malware_type = "RANSOMWARE"

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
        $x = "TZeppelinU" ascii wide

    condition:
        2 of ($s*) or $x
}rule ZLoader
{
    meta:
        id = "2JUpH4J7F9VVLnQm59k5t9"
        fingerprint = "b6cc36932d196457ad66df7815f1eb3a5e8561686d9184286a375bc78a209db0"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ZLoader in memory or unpacked."
        category = "MALWARE"
        malware = "ZLOADER"
        malware_type = "LOADER"


    strings:
        /*
            00104bc0 89 f8           MOV        EAX,EDI
            00104bc2 8b 0d 00        MOV        ECX,dword ptr [PTR_s_#Irb4utunQPhJZjSn_0010b000] = 0010a4d0
                     b0 10 00
            00104bc8 99              CDQ
            00104bc9 f7 7d f0        IDIV       dword ptr [EBP + local_14]
            00104bcc 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
            00104bcf 0f b6 1c 11     MOVZX      EBX,byte ptr [ECX + EDX*0x1]=>s_#Irb4utunQPhJZ   = "#Irb4utunQPhJZjSn"
            00104bd3 32 1c 38        XOR        BL,byte ptr [EAX + EDI*0x1]
            00104bd6 88 1c 3e        MOV        byte ptr [ESI + EDI*0x1],BL
            00104bd9 8d 7f 01        LEA        EDI,[EDI + 0x1]
        */
        $code = { 89 f8 8b 0d ?? ?? ?? ?? 99 f7 7? ?? 8b 4? ?? 0f b6 1c ?? 32
    1c 38 88 1c 3e 8d 7f 01 74 ?? e8 ?? ?? ?? ?? 80 fb 7f 74 ?? 38 c3 7d
    ?? 80 fb 0d 77 ?? 0f b6 c3 b9 00 26 00 00 0f a3 c1 72 ?? }
        $dll = "antiemule-loader-bot32.dll" ascii wide fullword
        $s1 = "/post.php" ascii wide
        $s2 = "BOT-INFO" ascii wide
        $s3 = "Connection: close" ascii wide
        $s4 = "It's a debug version." ascii wide
        $s5 = "Proxifier is a conflict program, form-grabber and web-injects will not works. Terminate proxifier for solve this problem." ascii wide
        $s6 = "rhnbeqcuwzbsjwfsynex" ascii wide fullword

    condition:
        $code or $dll or (4 of ($s*))
}
