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
}rule AgentTeslaV4JIT
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla V4 JIT native config extractor"
        cape_options = "bp0=$decode1+8,count=0,action0=string:ecx,typestring=AgentTesla Strings,no-logs=2"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
        $decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
        $decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}
    condition:
        2 of them
}

rule AgentTeslaV3JIT
{
    meta:
        author = "ClaudioWayne"
        description = "AgentTesla V3 JIT native string decryption"
        cape_options = "bp0=$decode+20,count=0,action0=string:eax+8,typestring=AgentTesla Strings,no-logs=2"
    strings:
        $decode = {8B C8 57 FF 75 08 8B [5] 8B 01 8B 40 3C FF [2] 8B F0 B8 03 00 00 00}
    condition:
        all of them
}
rule Agniane
{
    meta:
        author = "Any.RUN"
        reference = "https://twitter.com/MalGamy12/status/1703004559440769332"
        description = "Detects Agniane Stealer"
        date = "2023-09-20"
        hash1 = "abce9c19df38717374223d0c45ce2d199f77371e18f9259b9b145fe8d5a978af"

    strings:
        $x1 = "Agniane Stealer" wide nocase
        $x2 = "obj\\Release\\Agniane.pdb" ascii fullword

        $s1 = "System.Data.SQLite" wide
        $s2 = "Start collecting cookies from browsers" wide
        $s3 = "Start collecting files from Desktop and Documents" wide
        $s4 = "We start collecting a Telegram and Kotatogram sessions" wide
        $s5 = "Collection of cookies is complete. Total cookie lines:" wide
        $s6 = "ExecLogging" ascii fullword
        $s7 = "Execution Log.txt" wide fullword

    condition:
        uint16(0) == 0x5A4D and filesize < 600KB
            and
        (
            any of ($x*)
                or
            5 of ($s*)
        )

}rule Al_khaser
{
    meta:
        author = "kevoreilly"
        description = "Al-khaser bypass"
        cape_options = "bp0=$print_check_result_x86,bp0=$print_check_result_x64,action0=setecx:0,count=1,no-logs=2"
    strings:
        $print_check_result_x86 = {89 45 FC 53 56 8B C1 89 95 C4 FD FF FF 89 85 C8 FD FF FF 57 6A F5 83 F8 01 75 47 FF 15 [4] 8B D8 8D 8D E4 FD FF FF BA 16 00 00 00 66 90}
        $print_check_result_x64 = {48 89 84 24 50 02 00 00 8B F1 83 F9 01 B9 F5 FF FF FF 48 8B EA 75 41 FF 15 [4] 48 8D 7C 24 30 B9 16 00 00 00 48 8B D8}
    condition:
        uint16(0) == 0x5A4D and any of ($print_check_result*)
}
rule Amadey
{
    meta:
        author = "kevoreilly"
        description = "Amadey Payload"
        cape_type = "Amadey Payload"
        hash = "988258716d5296c1323303e8fe4efd7f4642c87bfdbe970fe9a3bb3f410f70a4"
    strings:
        $decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
        $decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
        $decode3 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
rule Andromeda
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
rule angler_ek_checkpoint
{
	meta:
		description = "Angler EK Exploit Kit - Checkpoint Detection"
	strings:
		$a = "Jul 2039" nocase
		$b = "Jul 2040" nocase
	condition:
		any of them
}rule AnglerEKredirector
{
   meta:
      description = "Angler Exploit Kit Redirector"
      ref = "http://blog.xanda.org/2015/08/28/yara-rule-for-angler-ek-redirector-js/"
      author = "adnan.shukor@gmail.com"
      date = "08-July-2015"
      impact = "5"
      version = "1"
   strings:
      $ekr1 = "<script>var date = new Date(new Date().getTime() + 60*60*24*7*1000);" fullword
      $ekr2 = "document.cookie=\"PHP_SESSION_PHP="
      $ekr3 = "path=/; expires=\"+date.toUTCString();</script>" fullword
      $ekr4 = "<iframe src=" fullword
      $ekr5 = "</iframe></div>" fullword
   condition:
      all of them
}rule angler_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "8081397c30b53119716c374dd58fc653"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(9OOSp"
	$string1 = "r$g@ 0'[A"
	$string2 = ";R-1qTP"
	$string3 = "xwBtR4"
	$string4 = "YbVjxp"
	$string5 = "ddgXkF"
	$string6 = ")n'URF"
	$string7 = "vAzq@W"
	$string8 = "rOkX$6m<"
	$string9 = "@@DB}q "
	$string10 = "TiKV'iV"
	$string11 = "538x;B"
	$string12 = "9pEM{d"
	$string13 = ".SIy/O"
	$string14 = "ER<Gu,"
condition:
	14 of them
}
rule angler_flash2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "23812c5a1d33c9ce61b0882f860d79d6"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "4yOOUj"
	$string1 = "CSvI4e"
	$string2 = "'fwaEnkI"
	$string3 = "'y4m%X"
	$string4 = "eOc)a,"
	$string5 = "'0{Q5<"
	$string6 = "1BdX;P"
	$string7 = "D _J)C"
	$string8 = "-epZ.E"
	$string9 = "QpRkP."
	$string10 = "<o/]atel"
	$string11 = "@B.,X<"
	$string12 = "5r[c)U"
	$string13 = "52R7F'"
	$string14 = "NZ[FV'P"
condition:
	14 of them
}
rule angler_flash4
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "dbb3f5e90c05602d92e5d6e12f8c1421"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "_u;cwD;"
	$string1 = "lhNp74"
	$string2 = "Y0GQ%v"
	$string3 = "qjqCb,nx"
	$string4 = "vn{l{Wl"
	$string5 = "5j5jz5"
	$string6 = "a3EWwhM"
	$string7 = "hVJb/4Aut"
	$string8 = ",lm4v,"
	$string9 = ",6MekS"
	$string10 = "YM.mxzO"
	$string11 = ";6 -$E"
	$string12 = "QA%: fy"
	$string13 = "<@{qvR"
	$string14 = "b9'$'6l"
	$string15 = ",x:pQ@-"
	$string16 = "2Dyyr9"
condition:
	16 of them
}
rule angler_flash5
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "9f809272e59ee9ecd71093035b31eec6"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0k%2{u"
	$string1 = "\\Pb@(R"
	$string2 = "ys)dVI"
	$string3 = "tk4_y["
	$string4 = "LM2Grx"
	$string5 = "n}s5fb"
	$string6 = "jT Nx<hKO"
	$string7 = "5xL>>}"
	$string8 = "S%,1{b"
	$string9 = "C'3g7j"
	$string10 = "}gfoh]"
	$string11 = ",KFVQb"
	$string12 = "LA;{Dx"
condition:
	12 of them
}
rule angler_flash_uncompressed
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "2543855d992b2f9a576f974c2630d851"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "DisplayObjectContainer"
	$string1 = "Xtime2"
	$string2 = "(HMRTQ"
	$string3 = "flash.events:EventDispatcher$flash.display:DisplayObjectContainer"
	$string4 = "_e_-___-__"
	$string5 = "ZviJbf"
	$string6 = "random-"
	$string7 = "_e_-_-_-_"
	$string8 = "_e_------"
	$string9 = "817677162"
	$string10 = "_e_-__-"
	$string11 = "-[vNnZZ"
	$string12 = "5:unpad: Invalid padding value. expected ["
	$string13 = "writeByte/"
	$string14 = "enumerateFonts"
	$string15 = "_e_---___"
	$string16 = "_e_-_-"
	$string17 = "f(fOJ4"
condition:
	17 of them
}
rule angler_html
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "afca949ab09c5583a2ea5b2006236666"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " A9 3E AF D5 9AQ FA 14 BC F2 A0H EA 7FfJ A58 A3 B1 BD 85 DB F3 B4 B6 FB B2 B4 14 82 19 88 28 D0 EA 2"
	$string1 = " 2BS 25 26p 20 3F 81 0E D3 9C 84 C7 EC C3 C41M C48 D3 B5N 09 C2z 98 7B 09. DF 05 5EQ DF A3 B6 EE D5 "
	$string2 = "9 A1Fg A8 837 9A A9 0A 1D 40b02 A5U6 22o 16 DC 5D F5 F5 FA BE FB EDX F0 87 DB C9 7B D6 AC F6D 10 1AJ"
	$string3 = "24 AA 17 FB B0 96d DBN 05 EE F6 0F 24 D4 D0 C0 E4 96 03 A3 03 20/ 04 40 DB 8F 7FI A6 DC F5 09 0FWV 1"
	$string4 = "Fq B3 94 E3 3E EFw E6 AA9 3A 5B 9E2 D2 EC AF6 10c 83 0F DF BB FBx AF B4 1BV 5C DD F8 9BR 97v D0U 9EG"
	$string5 = "29 9B 01E C85 86 B0 09 EC E07 AFCY 19 E5 11 1C 92 E2 DA A9 5D 19P 3A BF AB D6 B3 3FZ B4 92 FF E1 27 "
	$string6 = "B A9 88 B8 F0 EBLd 8E 08 18 11P EE BFk 15 5BM D6 B7 CEh AF 9C 8F 04 89 88 5E F6 ED 13 8EN1p 86Vk BC "
	$string7 = "w F4 C8 16pV 22 0A BB EB 83 7D BC 89 B6 E06 8B 2A DC E6 7D CE. 0Dh 18 0A8 5E 60 0C BF A4 00M 00 E3 3"
	$string8 = "B7 C6 E3 8E DC 3BR 60L 94h D8 AA7k5s 0D 7Fb 8B 80P E0 1BP EBT B5 03zE D0o 2A B97 18 F39 7C 94 99 11 "
	$string9 = "kY 24 8E 3E 94 84 D2 00 1EB 16 A4 9C 28 24 C1B BB 22 7D 97c F5 BA AD C4 5C 23 5D 3D 5C A7d5 0C F6 EA"
	$string10 = "08 01 3A 15 3B E0 1A E2 89 5B A2 F4 ED 87O F9l A99 124 27 BF BB A1c 2BW 12Z 07 AA D9 81 B7 A6-5 E2 E"
	$string11 = " 16 BF A7 0E 00 16 BB 8FB CBn FC D8 9C C7 EA AC C2q 85n A96I D1 9B FC8 BDl B8 3Ajf 7B ADH FD 20 88 F"
	$string12 = "  ML    "
	$string13 = " AEJ 3B C7 BFy EF F07X D3 A0 1E B4q C4 BE 3A 10 E7 A0 FE D1Jhp 89 A0sj 1CW 08 D5 F7 C8 C6 D5I 81 D2 "
	$string14 = "B 24 90 ED CEP C8 C9 9B E5 25 09 C6B- 2B 3B C7 28 C9 C62 EB D3 D5 ED DE A8 7F A9mNs 87 12 82 03 A2 8"
	$string15 = "A 3A A2L DFa 18 11P 00 7F1 BBbY FA 5E 04 C4 5D 89 F3S DAN B5 CAi 8D 0A AC A8 0A ABI E6 1E 89 BB 07 D"
	$string16 = "C B5 FD 0B F9 0Ch CE 01 14 8Dp AF 24 E0 E3 D90 DD FF B0 07 2Ad 0B 7D B0 B2 D8 BD E6 A7 CE E1 E4 3E5 "
	$string17 = "19 0C 85 14r/ 8C F3 84 2B 8C CF 90 93 E2 F6zo C3 D40 A6 94 01 02Q 21G AB B9 CDx 9D FB 21 2C 10 C3 3C"
	$string18 = "FAV D7y A0 C7Ld4 01 22 EE B0 1EY FAB BA E0 01 24 15g C5 DA6 19 EEsl BF C7O 9F 8B E8 AF 93 F52 00 06 "
condition:
	18 of them
}
rule angler_html2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "6c926bf25d1a8a80ab988c8a34c0102e"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "E 06 E7i 1E 91q 9C D0J 1D 9B 14 E7g 1D DD ECK 20c 40 C6 0C AFR5 3D 03 9Em EC 0CB C9 A9 DFw C9 ADP 5B"
	$string1 = "14Bc 5C 3Bp CB 2A 12 3D A56 AA 14 87 E3 81 8A 80h 27 1C 3A4 CE 12 AE FAy F0 8A 21 B8I AD 1E B9 2C D1"
	$string2 = "0J 95 83 CC 1C 95D CAD 1A EA F3 00 E9 DA_ F2 ED 3CM1 A0 01t 1B EE 2C B6AWKq BF CAY FE D8 F2 7C 96 92"
	$string3 = "A8MTCsn C9 DBu D3 10 A0 D4 AC A9 97 06Rn 01 DAK EFFN ADP AE 0E 8FJd 8F DA B6 25RO 18 2A 00 EA F9 8B "
	$string4 = "A3 EB C1 CE 1E C4ok C4 19 F2 A7 17 9FCoz B6- C6 25J BB 0B 8C1OZ E4 7B AEz F6 06A 5D C0 D7 E8 FF DB D"
	$string5 = " 07 DE A3 F8 B0 B3 20V A4 B2 C8 60 BD EEG 95 BB 04 1Ckw A4 80 E6 23 F02 FA 9C 9A 14F BDC 18 BE BD B4"
	$string6 = "7 D1 B9 9B AC 2AN BA D3 00 A9 1CJ3J C0V 8F 8E FC B6p9 00 E1 01 21j B3 27 FF C3 8E 2B 92 8B DEiUI C3 "
	$string7 = " 99 2C AF9 F9 3F5 A8 F0 1BU C8e/ 00Q B4 10 DD BC 9D 8A BF B2 17 8F BFd DB D1 B7 E66 21 96 86 1E B2 1"
	$string8 = "E86 DF9 22Tg E93 9Em 29 0A 5B B5m E2 DCIF D6 D2 F5B CF F7XkRv BE EA A6 C5 82p 5E B3 B4aD B9 3A E0 22"
	$string9 = " 7C 95.q D6f E8 1AE 17 82T 84 F1/O 82 C2q C7 FE 05C E4 E5W F5 0A E4l 12 3Brt 8A E0 E7 DDJ 1F 1F C4 A"
	$string10 = "4t 91iE BD 2C 95U E9 1C AE 5B 5B A3 9D B2 F9 0B B5 15S9 AB 9D 94 85 A6 F1 AF B6 FC CAt 91iE BD 2C 95"
	$string11 = "  </input>"
	$string12 = "2 D12 93 FD AB 0DKK AEN 40 DA 88 7B FA 3B 18 EE 09 92 ED AF A8b 07 002 0A A3S 04 29 F9 A3 EA BB E9 7"
	$string13 = "40 C6 0C AFR5E 15 07 EE CBg B3 C6 60G 92tFt D7E 7D F0 C4 A89 29 EC BA E1 D9 3D 23 F0 0B E0o 3E2c B3 "
	$string14 = "2 A3. A3 F1 D8 D4 A83K 9C AEu FF EA 02 F4 B8 A0 EE C9 7B 15 C1 07D 80 7C 10 864 96 E3 AA F8 99bgve D"
	$string15 = "C 7D DC 0A E9 0D A1k 85s 9D 24 8C D0k E1 7E 3AH E2 052 D8q 16 FC 96 0AR C0 EC 99K4 3F BE ED CC DBE A"
	$string16 = "40 DA 88 7B 9E 1A B3 FA DE 90U 5B BD6x 9A 0C 163 AB EA ED B4 B5 98 ADL B7 06 EE E5y B8 9B C9Q 00 E9 "
	$string17 = "F BF_ F9 AC 5B CC 0B1 7B 60 20c 40 C6 0C AFR5 0B C7D 09 9D E30 14 AC 027 B2 B9B A7 06 E3z DC- B2 60 "
	$string18 = "0 80 97Oi 8C 85 D2 1Bp CDv 11 05 D4 26 E7 FC 3DlO AE 96 D2 1B 89 7C 16H 11 86 D0 A6 B95 FC 01 C5 8E "
condition:
	18 of them
}
rule angler_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "3de78737b728811af38ea780de5f5ed7"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "myftysbrth"
	$string1 = "classPK"
	$string2 = "8aoadN"
	$string3 = "j5/_<F"
	$string4 = "FXPreloader.class"
	$string5 = "V4w\\K,"
	$string6 = "W\\Vr2a"
	$string7 = "META-INF/MANIFEST.MF"
	$string8 = "Na8$NS"
	$string9 = "_YJjB'"
condition:
	9 of them
}rule angler_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "482d6c24a824103f0bcd37fa59e19452"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "    2654435769,   Be"
	$string1 = "DFOMIqka "
	$string2 = ",  Zydr$>>16"
	$string3 = "DFOMIqka( 'OPPj_phuPuiwzDFo')"
	$string4 = "U0BNJWZ9J0vM43TnlNZcWnZjZSelQZlb1HGTTllZTm19emc0dlsYF13GvhQJmTZmbVMxallMdhWW948YWi t    P  b50GW"
	$string5 = "    auSt;"
	$string6 = " eval    (NDbMFR "
	$string7 = "jWUwYDZhNVyMI2TzykEYjWk0MDM5MA%ZQ1TD1gEMzj         3  D       ',"
	$string8 = "('fE').substr    (2    ,    1 "
	$string9 = ",  -1 "
	$string10 = "    )  );Zydr$  [ 1]"
	$string11 = " 11;PsKnARPQuNNZMP<9;PsKnARPQuNNZMP"
	$string12 = "new   Array  (2),  Ykz"
	$string13 = "<script> "
	$string14 = ");    CYxin "
	$string15 = "Zydr$    [    1]"
	$string16 = "var tKTGVbw,auSt, vnEihY, gftiUIdV, XnHs, UGlMHG, KWlqCKLfCV;"
	$string17 = "reXKyQsob1reXKyQsob3 "
condition:
	17 of them
}
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
}rule AntiCuckoo
{
    meta:
        author = "kevoreilly"
        description = "AntiCuckoo bypass: https://github.com/therealdreg/anticuckoo"
        cape_options = "bp0=$HKActivOldStackCrash+36,action0=jmp,count=1"
        hash = "ad5e52f144bb4a1dae3090978c6ecb4c7732538c9b62a6cedd32eccee6094be5"
    strings:
        $HKActivOldStackCrash = {5B 81 FB FA FA FA FA 74 01 41 3B E0 75 ?? 83 E9 0B 83 F9 04 7F 04 C6 45 ?? 00 89 4D ?? 89 65 ?? 80 7D ?? 00 74}
    condition:
        uint16(0) == 0x5A4D and all of them
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
}rule Arkei
{
    meta:
        author = "kevoreilly"
        description = "Arkei Payload"
        cape_type = "Arkei Payload"
    strings:
        $string1 = "Windows_Antimalware_Host_System_Worker"
        $string2 = "Arkei"
        $string3 = "Bitcoin\\wallet.dat"
        $string4 = "Ethereum\\keystore"

        $v1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii wide
        $v2 = "/c taskkill /im " fullword ascii
        $v3 = "card_number_encrypted FROM credit_cards" ascii
        $v4 = "\\wallet.dat" ascii
        $v5 = "Arkei/" wide
        $v6 = "files\\passwords." ascii wide
        $v7 = "files\\cc_" ascii wide
        $v8 = "files\\autofill_" ascii wide
        $v9 = "files\\cookies_" ascii wide
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 7 of ($v*))
}
rule AsyncRat
{
    meta:
        author = "kevoreilly, JPCERT/CC Incident Response Group"
        description = "AsyncRat Payload"
        cape_type = "AsyncRat Payload"
    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
        $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $string1 = "Pastebin" ascii wide nocase
        $string2 = "Pong" wide
        $string3 = "Stub.exe" ascii wide
        $kitty = "StormKitty" ascii
    condition:
        uint16(0) == 0x5A4D and not $kitty and ($salt and (2 of ($str*) or 1 of ($b*))) or (all of ($b*) and 2 of ($str*))
}
rule Atlas
{
    meta:
        author = "kevoreilly"
        description = "Atlas Payload"
        cape_type = "Atlas Payload"
    strings:
        $a1 = "bye.bat"
        $a2 = "task=knock&id=%s&ver=%s x%s&disks=%s&other=%s&ip=%s&pub="
        $a3 = "process call create \"cmd /c start vssadmin delete shadows /all /q"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule AuroraStealer {

    meta:
        author          = "Johannes Bader @viql"
        version         = "v1.0"
        tlp             = "TLP:WHITE"
        date            = "2022-12-14"
        description     = "detects Aurora Stealer samples"
        malpedia_family = "win.aurora_stealer"
        hash1_md5        = "51c153501e991f6ce4901e6d9578d0c8"
        hash1_sha1       = "3816f17052b28603855bde3e57db77a8455bdea4"
        hash1_sha256     = "c148c449e1f6c4c53a7278090453d935d1ab71c3e8b69511f98993b6057f612d"
        hash2_md5        = "65692e1d5b98225dbfb1b6b2b8935689"
        hash2_sha1       = "0b51765c175954c9e47c39309e020bcb0f90b783"
        hash2_sha256     = "5a42aa4fc8180c7489ce54d7a43f19d49136bd15ed7decf81f6e9e638bdaee2b"
        cape_type        = "AuroraStealer Payload"

    strings:
        $str_func_01 = "main.(*DATA_BLOB).ToByteArray"
        $str_func_02 = "main.Base64Encode"
        $str_func_03 = "main.Capture"
        $str_func_04 = "main.CaptureRect"
        $str_func_05 = "main.ConnectToServer"
        $str_func_06 = "main.CreateImage"
        $str_func_07 = "main.FileExsist"
        $str_func_08 = "main.GetDisplayBounds"
        $str_func_09 = "main.GetInfoUser"
        $str_func_10 = "main.GetOS"
        $str_func_11 = "main.Grab"
        $str_func_12 = "main.MachineID"
        $str_func_13 = "main.NewBlob"
        $str_func_14 = "main.NumActiveDisplays"
        $str_func_15 = "main.PathTrans"
        $str_func_16 = "main.SendToServer_NEW"
        $str_func_17 = "main.SetUsermame"
        $str_func_18 = "main.Zip"
        $str_func_19 = "main.base64Decode"
        $str_func_20 = "main.countupMonitorCallback"
        $str_func_21 = "main.enumDisplayMonitors"
        $str_func_22 = "main.getCPU"
        $str_func_23 = "main.getDesktopWindow"
        $str_func_24 = "main.getGPU"
        $str_func_25 = "main.getMasterKey"
        $str_func_26 = "main.getMonitorBoundsCallback"
        $str_func_27 = "main.getMonitorRealSize"
        $str_func_28 = "main.sysTotalMemory"
        $str_func_29 = "main.xDecrypt"
        $str_type_01 = "type..eq.main.Browser_G"
        $str_type_02 = "type..eq.main.STRUSER"
        $str_type_03 = "type..eq.main.Telegram_G"
        $str_type_04 = "type..eq.main.Crypto_G"
        $str_type_05 = "type..eq.main.ScreenShot_G"
        $str_type_06 = "type..eq.main.FileGrabber_G"
        $str_type_07 = "type..eq.main.FTP_G"
        $str_type_08 = "type..eq.main.Steam_G"
        $str_type_09 = "type..eq.main.DATA_BLOB"
        $str_type_10 = "type..eq.main.Grabber"
        $varia_01 = "\\User Data\\Local State"
        $varia_02 = "\\\\Opera Stable\\\\Local State"
        $varia_03 = "Reconnect 1"
        $varia_04 = "@ftmone"
        $varia_05 = "^user^"
        $varia_06 = "wmic path win32_VideoController get name"
        $varia_07 = "\\AppData\\Roaming\\Telegram Desktop\\tdata"
        $varia_08 = "C:\\Windows.old\\Users\\"
        $varia_09 = "ScreenShot"
        $varia_10 = "Crypto"
    condition:
        uint16(0) == 0x5A4D and
        (
            32 of ($str_*) or
            9 of ($varia_*)
        )
}rule AutoIT_Compiled
{
    meta:
        id = "1HD8y9jsBZi1HDN82XCpZx"
        fingerprint = "7d7623207492860e4196e8c8a493b874bb3042c83f19e61e1d958e79a09bc8f8"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compiled AutoIT script (as EXE). This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"

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
        last_modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies AutoIT script.  This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"

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
}rule Azer
{
    meta:
        author = "kevoreilly"
        description = "Azer Payload"
        cape_type = "Azer Payload"
    strings:
        $a1 = "webmafia@asia.com" wide
        $a2 = "INTERESTING_INFORMACION_FOR_DECRYPT.TXT" wide
        $a3 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"  //-----BEGIN PUBLIC KEY-----
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule Azorult
{
    meta:
        author = "kevoreilly"
        description = "Azorult Payload"
        cape_type = "Azorult Payload"
    strings:
        $code1 = {C7 07 3C 00 00 00 8D 45 80 89 47 04 C7 47 08 20 00 00 00 8D 85 80 FE FF FF 89 47 10 C7 47 14 00 01 00 00 8D 85 00 FE FF FF 89 47 1C C7 47 20 80 00 00 00 8D 85 80 FD FF FF 89 47 24 C7 47 28 80 00 00 00 8D 85 80 F5 FF FF 89 47 2C C7 47 30 00 08 00 00 8D 85 80 F1 FF FF 89 47 34 C7 47 38 00 04 00 00 57 68 00 00 00 90}
        $string1 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),\"unixepoch\")"
    condition:
        uint16(0) == 0x5A4D and all of them
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
}rule BadRabbit
{
    meta:
        author = "kevoreilly"
        description = "BadRabbit Payload"
        cape_type = "BadRabbit Payload"
    strings:
        $a1 = "caforssztxqzf2nm.onion" wide
        $a2 = "schtasks /Create /SC once /TN drogon /RU SYSTEM" wide
        $a3 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule BazaLoader
{
	meta:
		author = "ANY.RUN"
		description = "Detects BazaLoader"
		date = "2024-01-19"
		hash1 = "55dfa7907b2874b0fab13c6fc271f0a592b60f320cd43349805bd74c41a527d3"
		url = "https://app.any.run/tasks/50e879cc-2abd-49d2-857a-0e7bb21b166f"
		unpacked_example = "https://app.any.run/tasks/7431c3f9-7a87-41c2-ac1c-c00e391414d5"

	strings:
		// intentional mistakes in the path
		$x1 = "\\\\?\\C:\\Windows \\System32\\WINMM.dll" fullword wide
		$x2 = "C:\\Windows \\System32\\winSAT.exe" fullword wide
		// target file and directory
		$x3 = "c:\\windows\\system\\svchost.exe" fullword ascii
		// PDB parts
		$x4 = "\\Release\\sloader.pdb" ascii
		$x5 = "\\for_re_nat\\v5x_5" ascii
		// log messages
		$x6 = "[*] Data + param_offset(%d)+JPG_OFFSET:" fullword ascii
		$x7 = "[+] We get next CFG data from server:" fullword ascii
		// URL part
		$x8= "/?a=iamok_%s_%s" ascii
		// nickname
		$x9 = "barabaka666" fullword ascii

		$s_dll = "/steel_.dll" fullword ascii
		$s_mut = "Global\\AlreadyExist" fullword ascii

		$cmd1 = "advfirewall firewall add rule name=\"" wide
		$cmd2 = "WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName" fullword ascii
		$cmd3 = "schtasks /delete /TN \"" ascii
		$cmd4 = "schtasks /create /sc minute /ED \"" ascii
		$cmd5 = "Add-MpPreference -ExclusionPath \\\\?\\C:\\" wide

		$log1 = "[+] Mutex created " fullword ascii
		$log0 = "[*] UAC is bypassed now!" fullword ascii

		$url1 = ".onion/index.php" ascii
		$url2 = "/getlog.php?a=%s" ascii

		$tor = "TOR_GET HEADER:" fullword ascii

	condition:
		uint16(0) == 0x5a4d
		and (
			1 of ($x*)
			or (1 of ($s_*) and 3 of them)
			or 7 of them
		)
}rule Bazar
{
    meta:
        author = "kevoreilly"
        cape_type = "Bazar Payload"
    strings:
        $decode = {F7 E9 [0-2] C1 FA 0? 8B C2 C1 E8 1F 03 D0 6B C2 ?? 2B C8}
        $rsa    = {C7 00 52 53 41 33 48 8D 48 09 C7 40 04 00 08 00 00 4C 8D 05 [3] 00 C6 40 08 03 B8 09 00 00 00 [0-3] 48 8D 89 80 00 00 00 41 0F 10 00}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
rule BazarBackdoor
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
}rule BitPaymer
{
    meta:
        author = "kevoreilly"
        description = "BitPaymer Payload"
        cape_type = "BitPaymer Payload"

    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $antidefender = "TouchMeNot" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule blackhole1_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BlackHole1 Exploit Kit Detection"
	hash0 = "724acccdcf01cf2323aa095e6ce59cae"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Created-By: 1.6.0_18 (Sun Microsystems Inc.)"
	$string1 = "workpack/decoder.classmQ]S"
	$string2 = "workpack/decoder.classPK"
	$string3 = "workpack/editor.classPK"
	$string4 = "xmleditor/GUI.classmO"
	$string5 = "xmleditor/GUI.classPK"
	$string6 = "xmleditor/peers.classPK"
	$string7 = "v(SiS]T"
	$string8 = ",R3TiV"
	$string9 = "META-INF/MANIFEST.MFPK"
	$string10 = "xmleditor/PK"
	$string11 = "Z[Og8o"
	$string12 = "workpack/PK"
condition:
	12 of them
}
rule blackhole2_css
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "9664a16c65782d56f02789e7d52359cd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string1 = "background:url('%%?a=img&img=countries.gif')"
	$string2 = "background:url('%%?a=img&img=exploit.gif')"
	$string3 = "background:url('%%?a=img&img=oses.gif')"
	$string4 = "background:url('%%?a=img&img=browsers.gif')"
	$string5 = "background:url('%%?a=img&img=edit.png')"
	$string6 = "background:url('%%?a=img&img=add.png')"
	$string7 = "background:url('%%?a=img&img=accept.png')"
	$string8 = "background:url('%%?a=img&img=del.png')"
	$string9 = "background:url('%%?a=img&img=stat.gif')"
condition:
	18 of them
}
rule blackhole2_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "92e21e491a90e24083449fd906515684"
	hash1 = "98b302a504a7ad0e3515ab6b96d623f9"
	hash2 = "a91d885ef4c4a0d16c88b956db9c6f43"
	hash3 = "d8336f7ae9b3a4db69317aea105f49be"
	hash4 = "eba5daf0442dff5b249274c99552177b"
	hash5 = "02d8e6daef5a4723621c25cfb766a23d"
	hash6 = "dadf69ce2124283a59107708ffa9c900"
	hash7 = "467199178ac940ca311896c7d116954f"
	hash8 = "17ab5b85f2e1f2b5da436555ea94f859"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">links/</a></td><td align"
	$string1 = ">684K</td><td>"
	$string2 = "> 36K</td><td>"
	$string3 = "move_logs.php"
	$string4 = "files/"
	$string5 = "cron_updatetor.php"
	$string6 = ">12-Sep-2012 23:45  </td><td align"
	$string7 = ">  - </td><td>"
	$string8 = "cron_check.php"
	$string9 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string10 = "bhadmin.php"
	$string11 = ">21-Sep-2012 15:25  </td><td align"
	$string12 = ">data/</a></td><td align"
	$string13 = ">3.3K</td><td>"
	$string14 = "cron_update.php"
condition:
	14 of them
}
rule blackhole2_htm10
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "83704d531c9826727016fec285675eb1"
	hash1 = "103ef0314607d28b3c54cd07e954cb25"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash3 = "fd84d695ac3f2ebfb98d3255b3a4e1de"
	hash4 = "c7b417a4d650c72efebc2c45eefbac2a"
	hash5 = "c3c35e465e316a71abccca296ff6cd22"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash7 = "10ce7956266bfd98fe310d7568bfc9d0"
	hash8 = "60024caf40f4239d7e796916fb52dc8c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "</body></html>"
	$string1 = "/icons/back.gif"
	$string2 = ">373K</td><td>"
	$string3 = "/icons/unknown.gif"
	$string4 = ">Last modified</a></th><th><a href"
	$string5 = "tmp.gz"
	$string6 = ">tmp.gz</a></td><td align"
	$string7 = "nbsp;</td><td align"
	$string8 = "</table>"
	$string9 = ">  - </td><td>"
	$string10 = ">filefdc7aaf4a3</a></td><td align"
	$string11 = ">19-Sep-2012 07:06  </td><td align"
	$string12 = "><img src"
	$string13 = "file3fa7bdd7dc"
	$string14 = "  <title>Index of /files</title>"
	$string15 = "0da49e042d"
condition:
	15 of them
}
rule blackhole2_htm11
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "e89b56df597688c489f06a0a6dd9efed"
	hash1 = "06ba331ac5ae3cd1986c82cb1098029e"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash3 = "7cbb58412554327fe8b643204a046e2b"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash0 = "e89b56df597688c489f06a0a6dd9efed"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash7 = "530d31a0c45b79c1ee0c5c678e242c02"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "></th><th><a href"
	$string1 = "/icons/back.gif"
	$string2 = ">Description</a></th></tr><tr><th colspan"
	$string3 = "nbsp;</td><td align"
	$string4 = "nbsp;</td></tr>"
	$string5 = ">  - </td><td>"
	$string6 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string7 = "<h1>Index of /dummy</h1>"
	$string8 = ">Size</a></th><th><a href"
	$string9 = " </head>"
	$string10 = "/icons/blank.gif"
	$string11 = "><hr></th></tr>"
condition:
	11 of them
}
rule blackhole2_htm12
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
	hash1 = "6f27377115ba5fd59f007d2cb3f50b35"
	hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
	hash3 = "06997228f2769859ef5e4cd8a454d650"
	hash4 = "11062eea9b7f2a2675c1e60047e8735c"
	hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
	hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
	hash7 = "4ec720cfafabd1c9b1034bb82d368a30"
	hash8 = "ecd7d11dc9bb6ee842e2a2dce56edc6f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "  <title>Index of /data</title>"
	$string1 = "<tr><th colspan"
	$string2 = "</body></html>"
	$string3 = "> 20K</td><td>"
	$string4 = "/icons/layout.gif"
	$string5 = " <body>"
	$string6 = ">Name</a></th><th><a href"
	$string7 = ">spn.jar</a></td><td align"
	$string8 = ">spn2.jar</a></td><td align"
	$string9 = " <head>"
	$string10 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string11 = "> 10K</td><td>"
	$string12 = ">7.9K</td><td>"
	$string13 = ">Size</a></th><th><a href"
	$string14 = "><hr></th></tr>"
condition:
	14 of them
}
rule blackhole2_htm3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "018ef031bc68484587eafeefa66c7082"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/download.php"
	$string1 = "./files/fdc7aaf4a3 md5 is 3169969e91f5fe5446909bbab6e14d5d"
	$string2 = "321e774d81b2c3ae"
	$string3 = "/files/new00010/554-0002.exe md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
	$string4 = "./files/3fa7bdd7dc md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
	$string5 = "1603256636530120915 md5 is 425ebdfcf03045917d90878d264773d2"
condition:
	3 of them
}
rule blackhole2_htm4
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "926429bf5fe1fbd531eb100fc6e53524"
	hash1 = "7b6cdc67077fc3ca75a54dea0833afe3"
	hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
	hash3 = "bd819c3714dffb5d4988d2f19d571918"
	hash4 = "9bc9f925f60bd8a7b632ae3a6147cb9e"
	hash0 = "926429bf5fe1fbd531eb100fc6e53524"
	hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
	hash7 = "386cb76d46b281778c8c54ac001d72dc"
	hash8 = "0d95c666ea5d5c28fca5381bd54304b3"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "words.dat"
	$string1 = "/icons/back.gif"
	$string2 = "data.dat"
	$string3 = "files.php"
	$string4 = "js.php"
	$string5 = "template.php"
	$string6 = "kcaptcha"
	$string7 = "/icons/blank.gif"
	$string8 = "java.dat"
condition:
	8 of them
}
rule blackhole2_htm5
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
	hash1 = "a09bcf1a1bdabe4e6e7e52e7f8898012"
	hash2 = "40db66bf212dd953a169752ba9349c6a"
	hash3 = "25a87e6da4baa57a9d6a2cdcb2d43249"
	hash4 = "6f4c64a1293c03c9f881a4ef4e1491b3"
	hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
	hash2 = "40db66bf212dd953a169752ba9349c6a"
	hash7 = "4bdfff8de0bb5ea2d623333a4a82c7f9"
	hash8 = "b43b6a1897c2956c2a0c9407b74c4232"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ruleEdit.php"
	$string1 = "domains.php"
	$string2 = "menu.php"
	$string3 = "browsers_stat.php"
	$string4 = "Index of /library/templates"
	$string5 = "/icons/unknown.gif"
	$string6 = "browsers_bstat.php"
	$string7 = "oses_stat.php"
	$string8 = "exploits_bstat.php"
	$string9 = "block_config.php"
	$string10 = "threads_bstat.php"
	$string11 = "browsers_bstat.php"
	$string12 = "settings.php"
condition:
	12 of them
}
rule blackhole2_htm6
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "a5f94d7bdeb88b57be67132473e48286"
	hash1 = "2e72a317d07aa1603f8d138787a2c582"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash3 = "58265fc893ed5a001e3a7c925441298c"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash0 = "a5f94d7bdeb88b57be67132473e48286"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash7 = "95c6462d0f21181c5003e2a74c8d3529"
	hash8 = "9236e7f96207253b4684f3497bcd2b3d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "uniq1.png"
	$string1 = "edit.png"
	$string2 = "left.gif"
	$string3 = "infin.png"
	$string4 = "outdent.gif"
	$string5 = "exploit.gif"
	$string6 = "sem_g.png"
	$string7 = "Index of /library/templates/img"
	$string8 = "uniq1.png"
condition:
	8 of them
}
rule blackhole2_htm8
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
	hash1 = "1e2ba0176787088e3580dfce0245bc16"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash3 = "f5e16a6cd2c2ac71289aaf1c087224ee"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash7 = "6702efdee17e0cd6c29349978961d9fa"
	hash8 = "287dca9469c8f7f0cb6e5bdd9e2055cd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">Description</a></th></tr><tr><th colspan"
	$string1 = ">Name</a></th><th><a href"
	$string2 = "main.js"
	$string3 = "datepicker.js"
	$string4 = "form.js"
	$string5 = "<address>Apache/2.2.15 (CentOS) Server at online-moo-viii.net Port 80</address>"
	$string6 = "wysiwyg.js"
condition:
	6 of them
}
rule blackhole2_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "86946ec2d2031f2b456e804cac4ade6d"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "k0/3;N"
	$string1 = "g:WlY0"
	$string2 = "(ww6Ou"
	$string3 = "SOUGX["
	$string4 = "7X2ANb"
	$string5 = "r8L<;zYH)"
	$string6 = "fbeatbea/fbeatbee.classPK"
	$string7 = "fbeatbea/fbeatbec.class"
	$string8 = "fbeatbea/fbeatbef.class"
	$string9 = "fbeatbea/fbeatbef.classPK"
	$string10 = "fbeatbea/fbeatbea.class"
	$string11 = "fbeatbea/fbeatbeb.classPK"
	$string12 = "nOJh-2"
	$string13 = "[af:Fr"
condition:
	13 of them
}
rule blackhole2_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "add1d01ba06d08818ff6880de2ee74e8"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "6_O6d09"
	$string1 = "juqirvs.classPK"
	$string2 = "hw.classPK"
	$string3 = "a.classPK"
	$string4 = "w.classuS]w"
	$string5 = "w.classPK"
	$string6 = "YE}0vCZ"
	$string7 = "v)Q,Ff"
	$string8 = "%8H%t("
	$string9 = "hw.class"
	$string10 = "a.classmV"
	$string11 = "2CniYFU"
	$string12 = "juqirvs.class"
condition:
	12 of them
}
rule blackhole2_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "c7abd2142f121bd64e55f145d4b860fa"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "69/sj]]o"
	$string1 = "GJk5Nd"
	$string2 = "vcs.classu"
	$string3 = "T<EssB"
	$string4 = "1vmQmQ"
	$string5 = "Kf1Ewr"
	$string6 = "c$WuuuKKu5"
	$string7 = "m.classPK"
	$string8 = "chcyih.classPK"
	$string9 = "hw.class"
	$string10 = "f';;;;{"
	$string11 = "vcs.classPK"
	$string12 = "Vbhf_6"
condition:
	12 of them
}
rule blackhole2_pdf
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "d1e2ff36a6c882b289d3b736d915a6cc"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/StructTreeRoot 5 0 R/Type/Catalog>>"
	$string1 = "0000036095 00000 n"
	$string2 = "http://www.xfa.org/schema/xfa-locale-set/2.1/"
	$string3 = "subform[0].ImageField1[0])/Subtype/Widget/TU(Image Field)/Parent 22 0 R/F 4/P 8 0 R/T<FEFF0049006D00"
	$string4 = "0000000026 65535 f"
	$string5 = "0000029039 00000 n"
	$string6 = "0000029693 00000 n"
	$string7 = "%PDF-1.6"
	$string8 = "27 0 obj<</Subtype/Type0/DescendantFonts 28 0 R/BaseFont/KLGNYZ"
	$string9 = "0000034423 00000 n"
	$string10 = "0000000010 65535 f"
	$string11 = ">stream"
	$string12 = "/Pages 2 0 R%/StructTreeRoot 5 0 R/Type/Catalog>>"
	$string13 = "19 0 obj<</Subtype/Type1C/Length 23094/Filter/FlateDecode>>stream"
	$string14 = "0000003653 00000 n"
	$string15 = "0000000023 65535 f"
	$string16 = "0000028250 00000 n"
	$string17 = "iceRGB>>>>/XStep 9.0/Type/Pattern/TilingType 2/YStep 9.0/BBox[0 0 9 9]>>stream"
	$string18 = "<</Root 1 0 R>>"
condition:
	18 of them
}
rule blackhole_basic : exploit_kit
{
    strings:
        $a = /\.php\?.*:[a-zA-Z0-9\:]{6,}&.*&/
    condition:
        $a
}
rule BlackKingDom
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
}rule bleedinglife2_adobe_2010_1297_exploit
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "8179a7f91965731daa16722bd95f0fcf"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "getSharedStyle"
	$string1 = "currentCount"
	$string2 = "String"
	$string3 = "setSelection"
	$string4 = "BOTTOM"
	$string5 = "classToInstancesDict"
	$string6 = "buttonDown"
	$string7 = "focusRect"
	$string8 = "pill11"
	$string9 = "TEXT_INPUT"
	$string10 = "restrict"
	$string11 = "defaultButtonEnabled"
	$string12 = "copyStylesToChild"
	$string13 = " xmlns:xmpMM"
	$string14 = "_editable"
	$string15 = "classToDefaultStylesDict"
	$string16 = "IMEConversionMode"
	$string17 = "Scene 1"
condition:
	17 of them
}
rule bleedinglife2_adobe_2010_2884_exploit
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "b22ac6bea520181947e7855cd317c9ac"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "_autoRepeat"
	$string1 = "embedFonts"
	$string2 = "KeyboardEvent"
	$string3 = "instanceStyles"
	$string4 = "InvalidationType"
	$string5 = "autoRepeat"
	$string6 = "getScaleX"
	$string7 = "RadioButton_selectedDownIcon"
	$string8 = "configUI"
	$string9 = "deactivate"
	$string10 = "fl.controls:Button"
	$string11 = "_mouseStateLocked"
	$string12 = "fl.core.ComponentShim"
	$string13 = "toString"
	$string14 = "_group"
	$string15 = "addRadioButton"
	$string16 = "inCallLaterPhase"
	$string17 = "oldMouseState"
condition:
	17 of them
}
rule bleedinglife2_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "2bc0619f9a0c483f3fd6bce88148a7ab"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFPK"
	$string1 = "RequiredJavaComponent.classPK"
	$string2 = "META-INF/JAVA.SFm"
	$string3 = "RequiredJavaComponent.class"
	$string4 = "META-INF/MANIFEST.MF"
	$string5 = "META-INF/JAVA.DSAPK"
	$string6 = "META-INF/JAVA.SFPK"
	$string7 = "5EVTwkx"
	$string8 = "META-INF/JAVA.DSA3hb"
	$string9 = "y\\Dw -"
condition:
	9 of them
}
rule bleedinglife2_java_2010_0842_exploit
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "b14ee91a3da82f5acc78abd10078752e"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
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
rule Blister
{
    meta:
        author = "kevoreilly"
        description = "Blister Sleep Bypass"
        cape_options = "bp0=$sleep1+6,bp1=$sleep2+7,action0=setsignflag,action1=clearcarryflag,count=3"
        blister_hash = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
        blister_hash = "afb77617a4ca637614c429440c78da438e190dd1ca24dc78483aa731d80832c2"
    strings:
        $sleep1 = {FF FF 83 7D F0 00 (E9|0F 8?)}
        $sleep2 = {81 7D D8 90 B2 08 00 (E9|0F 8?)}
        $protect = {50 6A 20 8D 45 ?? 50 8D 45 ?? 50 6A FF FF D7}
        $lock = {56 33 F6 B9 FF FF FF 7F 89 75 FC 8B C1 F0 FF 45 FC 83 E8 01 75 F7}
        $comp = {6A 04 59 A1 [4] 8B 78 04 8B 75 08 33 C0 F3 A7 75 0B 8B 45 0C 83 20 00 33 C0 40 EB 02 33 C0}
     condition:
        uint16(0) == 0x5A4D and 2 of ($protect, $lock, $comp) and all of ($sleep*)
}
rule BroEx
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
rule BuerLoader
{
    meta:
        author = "kevoreilly"
        description = "BuerLoader RDTSC Trap Bypass"
        cape_options = "bp0=$trap+43,action0=skip,count=0"
    strings:
        $trap = {0F 31 89 45 ?? 6A 00 8D 45 ?? 8B CB 50 E8 [4] 0F 31}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule BumbleBeeLoader
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Loader"
        cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
    strings:
        $str_set = {C7 ?? 53 65 74 50}
        $str_path = {C7 4? 04 61 74 68 00}
        $openfile = {4D 8B C? [0-70] 4C 8B C? [0-70] 41 8B D? [0-70] 4? 8B C? [0-70] FF D?}
        $createsection = {89 44 24 20 FF 93 [2] 00 00 80 BB [2] 00 00 00 8B F? 74}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
        $iternaljob = "IternalJob"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule BumbleBeeShellcode
{
    meta:
        author = "kevoreilly"
        description = "BumbleBee Loader 2023"
        cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
        packed = "51bb71bd446bd7fc03cc1234fcc3f489f10db44e312c9ce619b937fad6912656"
    strings:
        $setpath = "setPath"
        $alloc = {B8 01 00 00 00 48 6B C0 08 48 8D 0D [2] 00 00 48 03 C8 48 8B C1 48 89 [3] 00 00 00 8B 44 [2] 05 FF 0F 00 00 25 00 F0 FF FF 8B C0 48 89}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
        $algo = {41 8B C1 C1 E8 0B 0F AF C2 44 3B C0 73 6A 4C 8B [3] 44 8B C8 B8 00 08 00 00 2B C2 C1 E8 05 66 03 C2 8B 94 [2] 00 00 00}
    condition:
        2 of them
}

rule Bumblebee
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Anti-VM Bypass"
        cape_options = "bp0=$antivm1+2,bp1=$antivm2+2,bp1=$antivm3+38,action0=jmp,action1=skip,count=0,force-sleepskip=1"
    strings:
        $antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
        $antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
        $antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15 [4] E8 [4] 84 c0}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule Carbanak
{
    meta:
        author = "enzok"
        description = "Carnbanak Payload"
        cape_type = "Carbanak Payload"
        sample = "c9c1b06cb9c9bd6fc4451f5e2847a1f9524bb2870d7bb6f0ee09b9dd4e3e4c84"
    strings:
        $sboxinit = {0F BE 02 4? 8D 05 [-] 4? 8D 4D ?? E8 [3] 00 33 F6 4? 8D 5D ?? 4? 63 F8 8B 45 ?? B? B1 E3 14 06}
        $decode_string = {0F BE 03 FF C9 83 F8 20 7D ?? B? 1F [3] 4? 8D 4A E2 EB ?? 3D 80 [3] 7D ?? B? 7F [3] 4? 8D 4A A1 EB ?? B? FF [3] 4? 8D 4A 81}
        $constants = {0F B7 05 [3] 00 0F B7 1D [3] 00 83 25 [3] 00 00 89 05 [3] 00 0F B7 05 [3] 00 89 1D [3] 00 89 05 [3] 00 33 C0 4? 8D 4D}
    condition:
        uint16(0) == 0x5A4D and 2 of them
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
rule CargoBayLoader
{
    meta:
        author = "kevoreilly"
        description = "CargoBayLoader anti-vm bypass"
        cape_options = "bp0=$jmp1+4,action0=skip,bp1=$jmp2+2,action1=skip,count=1,force-sleepskip=1"
        hash = "75e975031371741498c5ba310882258c23b39310bd258239277708382bdbee9c"
    strings:
        $jmp1 = {40 42 0F 00 0F 82 [2] 00 00 48 8D 15 [4] BF 04 00 00 00 41 B8 04 00 00 00 4C 8D [3] 4C 89 F1 E8}
        $jmp2 = {84 DB 0F 85 [2] 00 00 48 8D 15 [4] 41 BE 03 00 00 00 41 B8 03 00 00 00 4C 8D 7C [2] 4C 89 F9 E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Cerber
{
    meta:
        author = "kevoreilly"
        description = "Cerber Payload"
        cape_type = "Cerber Payload"
    strings:
        $code1 = {33 C0 66 89 45 8? 8D 7D 8? AB AB AB AB AB [0-2] 66 AB 8D 45 8? [0-3] E8 ?? ?? 00 00}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
rule CobaltStrikeBeacon
{
    meta:
        author = "ditekshen, enzo & Elastic"
        description = "Cobalt Strike Beacon Payload"
        cape_type = "CobaltStrikeBeacon Payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii
        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
        $ver3a = {69 68 69 68 69 6b ?? ?? 69}
        $ver3b = {69 69 69 69}
        $ver4a = {2e 2f 2e 2f 2e 2c ?? ?? 2e}
        $ver4b = {2e 2e 2e 2e}
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x00-0xff)
        $a2 = "Started service %s on %s" xor(0x00-0xff)
        $a3 = "%s as %s\\%s: %d" xor(0x00-0xff)
        $b_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
        $b_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
    condition:
        all of ($ver3*) or all of ($ver4*) or 2 of ($a*) or any of ($b*) or 5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)
}
rule CobaltStrikeStager
{
    meta:
        author = "@dan__mayer <daniel@stairwell.com>"
        description = "Cobalt Strike Stager Payload"
        cape_type = "CobaltStrikeStager Payload"
    strings:
        $smb = { 68 00 B0 04 00 68 00 B0 04 00 6A 01 6A 06 6A 03 52 68 45 70 DF D4 }
        $http_x86 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $http_x64 = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 49 89 E6 4C 89 F1 41 BA 4C 77 26 07 }
        $dns = { 68 00 10 00 00 68 FF FF 07 00 6A 00 68 58 A4 53 E5 }

    condition:
        any of them
}
rule Codoso
{
    meta:
        author = "kevoreilly"
        description = "Codoso Payload"
        cape_type = "Codoso Payload"
    strings:
        $a1 = "WHO_A_R_E_YOU?"
        $a2 = "DUDE_AM_I_SHARP-3.14159265358979"
        $a3 = "USERMODECMD"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
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
}rule Conti
{
    meta:
        author = "kevoreilly"
        description = "Conti Ransomware"
        cape_type = "Conti Payload"
    strings:
        $crypto1 = {8A 07 8D 7F 01 0F B6 C0 B9 ?? 00 00 00 2B C8 6B C1 ?? 99 F7 FE 8D [2] 99 F7 FE 88 ?? FF 83 EB 01 75 DD}
        $website1 = "https://contirecovery.info" ascii wide
        $website2 = "https://contirecovery.best" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
import "dotnet"
rule Costura_Protobuf
{
    meta:
        id = "2XP6PwlYvHaaVOgoVbFcQC"
        fingerprint = "da84b0a5628231b790fa802d404dcebd30c39805360e619ea78c6d56cf5d3c52"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Costura and Protobuf in .NET assemblies, respectively for storing resources and (de)serialization. Seen together might indicate a suspect binary."
        category = "INFO"
        reference_a = "https://github.com/Fody/Costura"
        reference_b = "https://github.com/protobuf-net/protobuf-net"
        reference_c = "https://any.run/cybersecurity-blog/pure-malware-family-analysis/"

strings:
    $comp = "costura.protobuf-net.dll.compressed" ascii wide fullword
    
condition:
    dotnet.is_dotnet and $comp
}
import "pe"

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
}rule crimepack_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit Detection"
	hash0 = "d48e70d538225bc1807842ac13a8e188"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "cpak/Crimepack$1.classPK"
	$string2 = "cpak/KAVS.classPK"
	$string3 = "cpak/KAVS.classmQ"
	$string4 = "cpak/Crimepack$1.classmP[O"
	$string5 = "META-INF/MANIFEST.MF"
	$string6 = "META-INF/MANIFEST.MFPK"
condition:
	6 of them
}
rule crimepack_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit Detection"
	hash0 = "40ed977adc009e1593afcb09d70888c4"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "payload.serPK"
	$string1 = "vE/JD[j"
	$string2 = "payload.ser["
	$string3 = "Exploit$2.classPK"
	$string4 = "Exploit$2.class"
	$string5 = "Ho((i/"
	$string6 = "META-INF/MANIFEST.MF"
	$string7 = "H5641Yk"
	$string8 = "Exploit$1.classPK"
	$string9 = "Payloader.classPK"
	$string10 = "%p6$MCS"
	$string11 = "Exploit$1$1.classPK"
condition:
	11 of them
}
rule CrunchyRoll
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
}rule Cryptoshield
{
    meta:
        author = "kevoreilly"
        description = "Cryptoshield Payload"
        cape_type = "Cryptoshield Payload"
    strings:
        $a1 = "CRYPTOSHIELD." wide
        $a2 = "Click on Yes in the next window for restore work explorer" wide
        $a3 = "r_sp@india.com - SUPPORT"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule cve_2013_0074
{
meta:
	author = "Kaspersky Lab"
	filetype = "Win32 EXE"
	date = "2015-07-23"
	version = "1.0"

strings:
	$b2="Can't find Payload() address" ascii wide
	$b3="/SilverApp1;component/App.xaml" ascii wide
	$b4="Can't allocate ums after buf[]" ascii wide
	$b5="------------ START ------------"

condition:
	( (2 of ($b*)) )
}rule CVE_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword 
        condition:
                (all of ($0422_*)) or (all of them)
}
rule DarkGate
{
    meta:
        author = "enzok"
        description = "DarkGate config"
        cape_options = "bp0=$config2+3,action0=dump:edx::1025,count=0,typestring=DarkGate Config"
        hash = "c1d35921f4fc3bac681a3d5148f517dc0ec90ab8c51e267c8c6cd5b1ca3dc085"
    strings:
        $part1 = {8B 55 ?? 8A 4D ?? 80 E1 3F C1 E1 02 8A 5D ?? 80 E3 30 81 E3 FF [3] C1 EB 04 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        $part2 = {8B 55 ?? 8A 4D ?? 80 E1 0F C1 E1 04 8A 5D ?? 80 E3 3C 81 E3 FF [3] C1 EB 02 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        $part3 = {8B 55 ?? 8A 4D ?? 80 E1 03 C1 E1 06 8A 5D ?? 80 E3 3F 02 CB 88 4C 10 FF FF 45}
        $alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
        $config1 = {B9 01 04 00 00 E8 [4] 8D 45}
        $config2 = {8B 55 ?? 8D 45 ?? E8 [4] 8D 45 ?? 5? B? 06 00 00 00 B? 01 00 00 00 8B 45 ?? E8 [4] 8B 45 ?? B? [4] E8 [4] 75}
    condition:
        ($alphabet) and (any of ($part*) or all of ($config*))
}
rule DarkGateLoader
{
    meta:
        author = "enzok"
        description = "DarkGate Loader"
        cape_options = "bp0=$decrypt1+30,bp0=$decrypt2+29,action0=dump:eax::ebx,bp1=$decrypt3+80,action1=dumpsize:eax,bp2=$decrypt3+124,hc2=1,action2=dump:eax,count=0"
        packed = "b15e4b4fcd9f0d23d902d91af9cc4e01417c426e55f6e0b4ad7256f72ac0231a"
    strings:
        $loader = {6C 6F 61 64 65 72}
        $decrypt1 = {B? 01 00 00 00 8B [3] E8 [4] 8B D7 32 54 [4] 88 54 18 FF 4? 4? 75}
        $decrypt2 = {B? 01 00 00 00 8B [2] E8 [4] 8B D7 2B D3 [4] 88 54 18 FF 4? 4? 75}
        $decrypt3 = {89 85 [4] 8B 85 [4] 8B F0 8D BD [4] B? 10 [3] F3 A5 8B 85 [4] 33 D2 [2] 8B 85 [4] 99}
    condition:
        $loader and any of ($decrypt*)
}
rule Darkside
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
}rule DoppelPaymer
{
    meta:
        author = "kevoreilly"
        description = "DoppelPaymer Payload"
        cape_type = "DoppelPaymer Payload"

    strings:
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $cmd_string = "Setup run\\n" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule DotNet_Reactor
{
    meta:
        id = "1zLgWF57AJIATVZNMOyilu"
        fingerprint = "43687ec89c0f6dc52e93395ae5966e25bc1c2d2c7634936b6e9835773af19fa3"
        version = "1.1"
        date = "2024-03-20"
        modified = "2024-04-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies .NET Reactor, which offers .NET code protection such as obfuscation, encryption and so on."
        category = "INFO"
        reference_a = "https://www.eziriz.com/dotnet_reactor.htm"
        reference_b = "https://unprotect.it/technique/net-reactor/"

strings:
    $s1 = "{11111-22222-20001-00001}" ascii wide fullword
    $s2 = "{11111-22222-20001-00002}" ascii wide fullword
    $s3 = "{11111-22222-40001-00001}" ascii wide fullword
    $s4 = "{11111-22222-40001-00002}" ascii wide fullword
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.1.}
    $x1 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.2.}
    $x2 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.1.}
    $x3 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.2.}
    $x4 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}

condition:
    2 of ($s*) or 2 of ($x*)
}
rule Dreambot
{
    meta:
        author = "kevoreilly"
        description = "Dreambot Payload"
        cape_type = "Dreambot Payload"
    strings:
        $a1 = {53 56 33 F6 33 DB C1 6C 24 0C 02 74 2F 8B 02 85 C0 75 11 83 7C 24 0C 02 76 0A 39 42 04 75 05 39 42 08 74 18 43 8A CB D3 C0 33 C6 33 44 24 10 8B F0 89 32 83 C2 04 FF 4C 24 0C 75 D1 5E 5B C2 08 00}
        $a2 = {53 33 C9 33 DB C1 6C 24 08 02 74 22 56 8B 02 85 C0 8B F0 74 18 33 C1 33 44 24 10 43 8A CB D3 C8 8B CE 89 02 83 C2 04 FF 4C 24 0C 75 E0 5E 5B C2 08 00}
        $b1 = "Oct  5 2016"
        $b2 = ".bss"
    condition:
        uint16(0) == 0x5A4D and (1 of ($a*)) and (all of ($b*))
}
rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "DridexLoader API Spam Bypass"
        cape_options = "bp0=$trap-13,action0=ret,count=0"
    strings:
        $trap = {6A 50 6A 14 6A 03 5A 8D 4C 24 ?? E8 [4] 68 [4] 68 [4] E8 [4] 85 C0 74 05}
    condition:
        uint16(0) == 0x5A4D and $trap
}
rule DridexV4
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 Payload"
        cape_type = "DridexV4 Payload"
    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $getproc64 = {81 FB ?? ?? ?? ?? 75 04 33 C0 EB 2D 8B CB E8 ?? ?? ?? ?? 48 85 C0 75 17 8B CB E8 ?? ?? ?? ?? 84 C0 74 E5 8B CB E8 ?? ?? ?? ?? 48 85 C0 74 D9 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $bot_stub_32 = {8B 45 E? 8? [5-13] 8A 1C 0? [6-15] 05 FF 00 00 00 8B ?? F? 39 ?? 89 45 E? 72 D?}
        $bot_stub_64 = {8B 44 24 ?? 89 C1 89 CA 4C 8B 05 [4] 4C 8B 4C 24 ?? 45 8A 14 11 83 E0 1F 89 C0 41 89 C3 47 2A 14 18 44 88 54 14}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule Ekans
{
    meta:
        id = "6Kzy2bA2Zj7kvpXriuZ14m"
        fingerprint = "396b915c02a14aa809060946c9294f487a5107ab37ebefb6d5cde07de4113d43"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2023-12-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "EKANS"
        malware_type = "RANSOMWARE"

    strings:
        $ = "already encrypted!" ascii wide
        $ = "error encrypting %v : %v" ascii wide
        $ = "faild to get process list" ascii wide
        $ = "There can be only one" ascii wide fullword
        $ = "total lengt: %v" ascii wide fullword

    condition:
        3 of them
}
rule eleonore_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "ad829f4315edf9c2611509f3720635d2"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "dev/s/DyesyasZ.classPK"
	$string2 = "k4kjRv"
	$string3 = "dev/s/LoaderX.class}V[t"
	$string4 = "dev/s/PK"
	$string5 = "Hsz6%y"
	$string6 = "META-INF/MANIFEST.MF"
	$string7 = "dev/PK"
	$string8 = "dev/s/AdgredY.class"
	$string9 = "dev/s/DyesyasZ.class"
	$string10 = "dev/s/LoaderX.classPK"
	$string11 = "eS0L5d"
	$string12 = "8E{4ON"
condition:
	12 of them
}
rule eleonore_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "94e99de80c357d01e64abf7dc5bd0ebd"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
	$string1 = "wPVvVyz"
	$string2 = "JavaFX.class"
	$string3 = "{%D@'\\"
	$string4 = "JavaFXColor.class"
	$string5 = "bWxEBI}Y"
	$string6 = "$(2}UoD"
	$string7 = "j%4muR"
	$string8 = "vqKBZi"
	$string9 = "l6gs8;"
	$string10 = "JavaFXTrueColor.classeSKo"
	$string11 = "ZyYQx "
	$string12 = "META-INF/"
	$string13 = "JavaFX.classPK"
	$string14 = ";Ie8{A"
condition:
	14 of them
}
rule eleonore_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "f65f3b9b809ebf221e73502480ab6ea7"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "16lNYF2V"
	$string1 = "META-INF/MANIFEST.MFPK"
	$string2 = "ghsdr/Jewredd.classPK"
	$string3 = "ghsdr/Gedsrdc.class"
	$string4 = "e[<n55"
	$string5 = "ghsdr/Gedsrdc.classPK"
	$string6 = "META-INF/"
	$string7 = "na}pyO"
	$string8 = "9A1.F\\"
	$string9 = "ghsdr/Kocer.class"
	$string10 = "MXGXO8"
	$string11 = "ghsdr/Kocer.classPK"
	$string12 = "ghsdr/Jewredd.class"
condition:
	12 of them
}
rule eleonore_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "08f8488f1122f2388a0fd65976b9becd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var de"
	$string1 = "sdjk];"
	$string2 = "return dfshk;"
	$string3 = "function jkshdk(){"
	$string4 = "'val';"
	$string5 = "var sdjk"
	$string6 = "return fsdjkl;"
	$string7 = " window[d"
	$string8 = "var fsdjkl"
	$string9 = "function jklsdjfk() {"
	$string10 = "function rewiry(yiyr,fjkhd){"
	$string11 = " sdjd "
condition:
	11 of them
}
rule eleonore_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "2f5ace22e886972a8dccc6aa5deb1e79"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var dfshk "
	$string1 = "arrow_next_down"
	$string2 = "return eval('yiyr.replac'"
	$string3 = "arrow_next_over"
	$string4 = "arrow_prev_over"
	$string5 = "xcCSSWeekdayBlock"
	$string6 = "xcCSSHeadBlock"
	$string7 = "xcCSSDaySpecial"
	$string8 = "xcCSSDay"
	$string9 = " window[df "
	$string10 = "day_special"
	$string11 = "var df"
	$string12 = "function jklsdjfk() {"
	$string13 = " sdjd "
	$string14 = "'e(/kljf hdfk sdf/g,fjkhd);');"
	$string15 = "arrow_next"
condition:
	15 of them
}
rule eleonore_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "9dcb8cd8d4f418324f83d914ab4d4650"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "@mozilla.org/file/directory_service;1"
	$string1 = "var exe "
	$string2 = "var file "
	$string3 = "foStream.write(data, data.length);"
	$string4 = "  var file_data "
	$string5 = "return "
	$string6 = " Components.classes["
	$string7 = "url : "
	$string8 = "].createInstance(Components.interfaces.nsILocalFile);"
	$string9 = "  var bstream "
	$string10 = " bstream.readBytes(size); "
	$string11 = "@mozilla.org/supports-string;1"
	$string12 = "  var channel "
	$string13 = "tmp.exe"
	$string14 = "  if (channel instanceof Components.interfaces.nsIHttpChannel "
	$string15 = "@mozilla.org/network/io-service;1"
	$string16 = " bstream.available()) { "
	$string17 = "].getService(Components.interfaces.nsIIOService); "
condition:
	17 of them
}
rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"
    strings:
        $snippet1 = {FF 15 [4] 83 C4 0C 68 40 00 00 F0 6A 18}
        $snippet3 = {83 3D [4] 00 C7 05 [8] C7 05 [8] 74 0A 51 E8 [4] 83 C4 04 C3 33 C0 C3}
        $snippet4 = {33 C0 C7 05 [8] C7 05 [8] A3 [4] A3 [19] 00 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 83 C4 04 C3}
        $snippet5 = {8B E5 5D C3 B8 [4] A3 [4] A3 [4] 33 C0 21 05 [4] A3 [4] 39 05 [4] 74 18 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 59 C3}
        $snippet6 = {33 C0 21 05 [4] A3 [4] 39 05 [4] 74 18 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 59 C3}
        $snippet7 = {8B 48 ?? C7 [5-6] C7 40 [4] ?? C7 [2] 00 00 00 [0-1] 83 3C CD [4] 00 74 0E 41 89 48 ?? 83 3C CD [4] 00 75 F2}
        $snippet8 = {85 C0 74 3? B9 [2] 40 00 33 D2 89 ?8 [0-1] 89 [1-2] 8B [1-2] 89 [1-2] EB 0? 41 89 [1-2] 39 14 CD [2] 40 00 75 F? 8B CE E8 [4] 85 C0 74 05 33 C0 40 5E C3}
        $snippet9 = {85 C0 74 4? 8B ?8 [0-1] C7 40 [5] C7 [5-6] C7 40 ?? 00 00 00 00 83 3C CD [4] 00 74 0? 41 89 [2-3] 3C CD [4] 00 75 F? 8B CF E8 [4] 85 C0 74 07 B8 01 00 00 00 5F C3}
        $snippetA = {85 C0 74 5? 8B ?8 04 89 78 28 89 38 89 70 2C EB 04 41 89 48 04 39 34 CD [4] 75 F3 FF 75 DC FF 75 F0 8B 55 F8 FF 75 10 8B 4D EC E8 [4] 83 C4 0C 85 C0 74 05}
        $snippetB = {EB 04 4? 89 [2] 39 [6] 75 F3}
        $snippetC = {EB 03 4? 89 1? 39 [6] 75 F4}
        $snippetD = {8D 44 [2] 50 68 [4] FF 74 [2] FF 74 [2] 8B 54 [2] 8B 4C [2] E8}
        $snippetE = {FF 74 [2] 8D 54 [2] FF 74 [2] 68 [4] FF 74 [2] 8B 4C [2] E8 [4] 8B 54 [2] 83 C4 10 89 44 [2] 8B F8 03 44 [2] B9 [4] 89 44 [2] E9 [2] FF FF}
        $snippetF = {FF 74 [2] 8D 44 [2] BA [4] FF 74 [2] 8B 4C [2] 50 E8 [4] 8B 54 [2] 8B D8 8B 84 [5] 83 C4 0C 03 C3 89 5C [2] 8B FB 89 44}
        $snippetG = {FF 74 [2] 8B 54 [2] 8D 44 [2] 8B 4C [2] 50 E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 89 44}
        $snippetH = {FF 74 [2] 8D 84 [5] 68 [4] 50 FF 74 [2] 8B 54 [2] 8B 4C [2] E8 [4] 8B 94 [5] 83 C4 10 89 84 [5] 8B F8 03 84}
        $snippetI = {FF 74 [2] 8D 8C [5] FF 74 [2] 8B 54 [2] E8 [4] 8B 54 [2] 8B D8 8B 84 [5] 83 C4 0C 03 C3 89 5C [2] 8B FB 89 44 24 74}
        $snippetJ = {FF 74 [2] 8B 4C [2] 8D 44 [2] 50 BA [4] E8 [4] 8B 54 [2] 8B F8 59 89 44 [2] 03 44 [2] 59 89 44 [2] B9 [4] E9}
        $snippetK = {FF 74 [2] FF 74 [2] 8B 54 [2] E8 [4] 8B 54 [2] 83 C4 0C 89 44 [2] 8B F8 03 44 [2] B9 [4] 89 44 [2] E9}
        $snippetL = {FF 74 [2] 8B 54 [2] 8D 4C [2] E8 [4] 59 89 44 [2] 8B F8 03 44 [2] 59 89 44 24 68 B9 [4] E9}
        $snippetM = {FF 74 [2] 8D 84 [3] 00 00 B9 [4] 50 FF 74 [2] FF 74 [2] 8B 94 [3] 00 00 E8 [4] 83 C4 10 89 44 [2] 8B F8 B9 [4] 03 84 [3] 00 00 89 44 [2] E9}
        $snippetN = {FF 74 [2] 8D 44 [2] B9 [4] FF 74 [2] 50 FF 74 [2] 8B 54 [2] E8 [4] 8B 8C [3] 00 00 83 C4 10 03 C8 89 44 [2] 89 4C [2] 8B F8 B9 45 89 77 05 E9}
        $snippetO = {8D 44 [2] B9 [4] 50 FF 74 [2] 8B 54 [2] E8 [4] 8B D0 8B 44 [2] 59 59 03 C2 89 54 [2] 8B FA 89 44 [2] B9 [4] E9}
        $snippetP = {FF 74 [2] 8B 54 [2] 8D 44 [2] 8B 4C [2] 68 [4] 50 E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 8B 54 [2] B9 [4] 89 44 [2] E9}
        $snippetQ = {FF 74 [2] BA [4] 8D 4C [2] FF 74 [2] E8 [4] 59 89 84 [3] 00 00 8B F8 03 44 [2] 59 89 44 [2] B9 [4] 81 F9 [4] 74 28 8B 54 [2] E9}
        $snippetR = {8D 44 [2] 50 FF 74 [2] 8B 54 [2] 8B 4C [2] 68 [4] E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 8B 54 [2] B9 [4] 89 44 [2] E9}
        $snippetS = {FF 74 [2] 8D 54 [2] FF 74 [2] 8B 4C [2] E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 8B 54 [2] B9 [4] 89 44 [2] E9}
        $snippetT = {8B 54 [2] 8D 44 [2] 8B 4C [2] 68 [4] 50 E8 [4] 8B 9C [3] 00 00 8B F8 59 59 03 D8 89 44 [2] 89 5C [2] B9 [4] EB}
        $snippetU = {89 44 [2] 33 D2 8B 44 [2] F7 F1 B9 [4] 89 44 [2] 8D 44 [2] 81 74 [6] C7 44 [6] 81 44 [6] 81 74 [6] FF 74 [2] 50 FF 74 [2] FF 74 [2] 8B 54 [2] E8}
        $snippetV = {81 74 [2] ED BC 9C 00 FF 74 [2] 50 68 [4] FF 74 [2] 8B 54 [2] 8B 4C [2] E8}
        $snippetW = {4C 8D [2] 8B [2] 4C 8D 05 [4] F7 E1 2B CA D1 E9 03 CA C1 E9 06 89}
        $snippetX = {4C 8D 0? [2] (00|01) 00 [0-80] 48 8D [0-9] 81 75 [5] C7 45 [5-14] 81}
        $snippetY = {(3D [4] 0F 84 [4] 3D [4] 0F 85 [3] ??|B8 [4] E9 [3] ??) 48 8D 05 [4] 48 89 (81 [3] ??|41 ??) 48 8D 05 [4] 48 89 (81 [3] ??|41 ??) 48 8D 05 [4] 48 89}
        $snippetZ = {(48 8B D8 48 85 C0 0F 84 [4-9] E9 [4-190] ?? | 55 53 48 8D AC 24 [2] FF FF 48 81 EC [2] 00 00 48 8B [3] 00 00 [0-80] ??) 48 8D 05 [4] 48 89 (85 [3] ??|4? ??) [0-220] 48 8D 05 [4] 48 89 (85 [3] ??|4? ??) [0-220] 48 8D 05 [4] 48 89 (85 [3] ??|4? ??)}
        $comboA1 = {83 EC 28 56 FF 75 ?? BE}
        $comboA2 = {83 EC 38 56 57 BE}
        $comboA3 = {EB 04 40 89 4? ?? 83 3C C? 00 75 F6}
    condition:
        uint16(0) == 0x5A4D and any of ($snippet*) or 2 of ($comboA*)
}
rule EmotetLoader
{
    meta:
        author = "kevoreilly"
        description = "Emotet Loader"
        cape_type = "EmotetLoader Payload"
    strings:
        $antihook = {8B 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 95 28 FF FF FF A1 ?? ?? ?? ?? 2D 4D 01 00 00 A3 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 3B 0D ?? ?? ?? ?? 76 26 8B 95 18 FF FF FF 8B 42 38}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and any of them
}
rule EmotetPacker
{
    meta:
        author = "kevoreilly"
        description = "Emotet bypass"
        cape_options = "bp0=$trap1+31,action0=skip,bp1=$trap2+43,action1=jmp:186,count=1"
        hash = "5a95d1d87ce69881b58a0e3aafc1929861e2633cdd960021d7b23e2a36409e0d"
    strings:
        $trap1 = {8B 45 08 0F 28 0D [4] 0F 57 C0 0F 29 46 30 89 46 40 C7 46 44 00 00 00 00 0F 11 4E 48 E8}
        $trap2 = {F2 0F 10 15 [4] BE 01 00 00 00 0F 01 F9 C7 44 24 60 00 00 00 00 89 4C 24 60 0F 01 F9 C7 44 24 5C 00 00 00 00 89 4C 24 5C 0F 1F 84 00 00 00 00 00}
    condition:
        uint16(0) == 0x5A4D and any of ($trap*)
}
rule EnigmaStub
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
}rule EternalRomance
{
    meta:
        author = "kevoreilly"
        description = "EternalRomance Exploit"
        cape_type = "EternalRomance Exploit"
    strings:
        $SMB1 = "Frag"
        $SMB2 = "Free"
        $session7_32_1 = {2A 02 1C 00}
        $session7_64_1 = {2A 02 28 00}
        $session8_32_1 = {2A 02 24 00}
        $session8_64_1 = {2A 02 38 00}
        $session7_32_2 = {D5 FD E3 FF}
        $session7_64_2 = {D5 FD D7 FF}
        $session8_32_2 = {D5 FD DB FF}
        $session8_64_2 = {D5 FD C7 FF}
        $ipc = "IPC$"
        $pipe1 = "atsvc"
        $pipe2 = "browser"
        $pipe3 = "eventlog"
        $pipe4 = "lsarpc"
        $pipe5 = "netlogon"
        $pipe6 = "ntsvcs"
        $pipe7 = "spoolss"
        $pipe8 = "samr"
        $pipe9 = "srvsvc"
        $pipe10 = "scerpc"
        $pipe11 = "svcctl"
        $pipe12 = "wkssvc"
    condition:
        uint16(0) == 0x5A4D and (all of ($SMB*)) and $ipc and (any of ($session*)) and (any of ($pipe*))
}
rule Exela
{
    meta:
        author = "Any.RUN"
        reference = "https://twitter.com/MalGamy12/status/1703704904039047273"
        description = "Detects Exela Stealer"
        date = "2023-09-20"
        hash1 = "bf5d70ca2faf355d86f4b40b58032f21e99c3944b1c5e199b9bb728258a95c1b"
        hash2 = "e9e59ca2c8e786f92e81134f088ea08c53fc4c8c252871613ccc51b473814633"

    strings:
        $x1 = "Exela Stealer" wide nocase
        $x2 = "Exela\\Exela\\obj\\Release\\Exela.pdb" ascii fullword

        $s1 = "discord.com/api/webhooks" wide
        $s2 = "wifi.txt" wide
        $s3 = "network.txt" wide
        $s4 = "Autofills.txt" wide
        $s5 = "Downloads.txt" wide
        $s6 = "Cookies.txt" wide
        $s7 = "Passwords.txt" wide
        $s8 = "Cards.txt" wide
        $s9 = "Mutex already exist." wide
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

}import "dotnet"

rule FakeCheck
{
	meta:
		author = "Any.RUN"
		reference = "https://twitter.com/MalGamy12/status/1701121339061358907"
		description = "Detects FakeCheck Stealer"
		date = "2023-09-11"
		hash1 = "012063e0b7b4f7f3ce50574797112f95492772a9b75fc3d0934a91cc60faa240"

	strings:
		$x1 = "D:\\MyProjects\\SelfTraining\\Csharp\\ReconApp-Final\\ReconApp\\obj\\x64\\Release\\alg.pdb" ascii fullword
		$x2 = "https://tosals.ink/uEH5J.html" wide fullword

		// mistake in "Volume"
		$a1 = "System Volumn Information" wide fullword
		$a2 = "Fatal error" wide fullword
		$a3 = "Please reinstall .net 3.5 first!" wide fullword

		$s1 = "\\AppData\\Local\\Comms" fullword wide
		$s2 = "\\AppData\\Local\\D3DSCache" fullword wide
		$s3 = "\\AppData\\Local\\OneDrive" fullword wide
		$s4 = "\\AppData\\Local\\Packages" fullword wide
		$s5 = "Content-Disposition: form-data; name=\"file\"; filename=\"{1}\"" fullword wide
		$s6 = "Program Files (x86)\\AhnLab" fullword wide
		$s7 = "Total size of drive : {0}" fullword wide
		$s8 = "Available space to current user : {0}" fullword wide

	condition:
		dotnet.is_dotnet and
		/*
		//// for yara version < 4.2.0 ////
		//// don't forget: import "pe" ////
		uint16(0) == 0x5a4d and
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size != 0 and
		*/
		(
			any of ($x*) or
			2 of ($a*) or
			7 of ($s*)
		)
}
rule Fareit
{
    meta:
        author = "kevoreilly"
        description = "Fareit Payload"
        cape_type = "Fareit Payload"
    strings:
        $string1 = {0D 0A 09 09 0D 0A 0D 0A 09 20 20 20 3A 6B 74 6B 20 20 20 0D 0A 0D 0A 0D 0A 20 20 20 20 20 64 65 6C 20 20 20 20 09 20 25 31 20 20 0D 0A 09 69 66 20 20 09 09 20 65 78 69 73 74 20 09 20 20 20 25 31 20 20 09 20 20 67 6F 74 6F 20 09 0D 20 6B 74 6B 0D 0A 20 64 65 6C 20 09 20 20 25 30 20 00}
    condition:
        uint16(0) == 0x5A4D and any of ($string*)
}
rule Formbook
{
    meta:
        author = "kevoreilly"
        description = "Formbook Payload"
        cape_type = "Formbook Payload"
        packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
        packed = "2379a4e1ccdd7849ad7ea9e11ee55b2052e58dda4628cd4e28c3378de503de23"
    strings:
        $remap_ntdll = {33 56 0? 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
        $rc4dec = {F7 E9 C1 FA 03 8B C2 C1 E8 1F 03 C2 8D 04 80 03 C0 03 C0 8B D1 2B D0 8A 04 3A 88 8C 0D [4] 88 84 0D [4] 41 81 F9 00 01 00 00 7C}
        $decrypt = {8A 50 01 28 10 48 49 75 F7 83 FE 01 76 14 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 75 F7}
        $string = {33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8B 55 0C 8D 44 00 02 50 52 51 E8}
        $mutant = {64 A1 18 00 00 00 8B 40 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 8B E5 5D C3}
        $postmsg = {8B 7D 0C 6A 00 6A 00 68 11 01 00 00 57 FF D6 85 C0 75 ?? 50}
    condition:
        2 of them
}rule fragus_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f76deec07a61b4276acc22beef41ea47"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">Hello, "
	$string1 = "http://www.clantemplates.com"
	$string2 = "this template was created by Bl1nk and is downloadable at <B>ClanTemplates.com<BR></B>Replace "
	$string3 = "></TD></TR></TABLE> "
	$string4 = "Image21"
	$string5 = "scrollbar etc.<BR><BR>Enjoy, Bl1nk</FONT></TD></TR></TABLE><BR></CENTER></TD></TR> "
	$string6 = "to this WarCraft Template"
	$string7 = " document.getElementById) x"
	$string8 = "    if (a[i].indexOf("
	$string9 = "x.oSrc;"
	$string10 = "x.src; x.src"
	$string11 = "<HTML>"
	$string12 = "FFFFFF"
	$string13 = " CELLSPACING"
	$string14 = "images/layoutnormal_03.gif"
	$string15 = "<TR> <TD "
	$string16 = " CELLPADDING"
condition:
	16 of them
}
rule fragus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "));ELI6Q3PZ"
	$string1 = "VGhNU2pWQmMyUXhPSFI2TTNCVGVEUXpSR3huYm1aeE5UaFhXRFI0ZFhCQVMxWkRNVGh0V0hZNFZVYzBXWFJpTVRoVFpFUklaVGxG"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "TkhXa0ZrT1haNGRFSXhRM3BrTkRoVGMxZEJSMmcyT0dwNlkzSTJYM1pCYkZnMVVqQmpWMEZIYURZNGFucGpjalpmZGtGc1dERXpT"
	$string4 = "byKZKkpZU<<18"
	$string5 = ");CUer0x"
	$string6 = "bzWRebpU3yE>>16"
	$string7 = "RUJEWlVvMGNsVTVNMEpNWDNaNGJVSkpPRUJrUlVwRVQwQlNaR2cyY0ZWSE5GbDBRVFZ5UjFnMk9HVldOWGhMYUdFelRIZG5NMWQz"
	$string8 = "WnZSVGxuT1ZSRkwwaFZSelZGUm5GRlJFVTBLVHQ0UWxKQ1drdzBiWEJ5WkhSdVBtdG9XVWd6TVVGSGFFeDVTMlk3ZUVKU1FscE1O"
	$string9 = "QmZjMGN4YjBCd1oyOXBURUJJZEhvMFdYcGtOamhFV1ZwU01GVlZZbXBpUUZKV1lqTXpWMDAwY0dSNlF6aE1SekZ5ZEc4ME9FeEtN"
	$string10 = "SCpMaWXOuME("
	$string11 = "VjJKcVkxZGlYMTlhUVdRNVNUTkhaRFk0YWpsYWJsWkRNVGh0V0hZNFZVYzBXWFJ2Tm5CVmFEUlpWVmhDT0ZWV05YaDBRa1ZTUkUw"
	$string12 = "2;}else{Yuii37DWU"
	$string13 = "ELI6Q3PZ"
	$string14 = "ZUhNNVZYQlZlRFY0UUZnMk9HMVlORkpFYkRsNGMxbEpPRUJSTVY5SGNETllPRXB0YjBsaloySnhPVVZ3UkZWQVgzTllORGgwV0RS"
	$string15 = "S05GbE1lalk0Vm1ORmVEWnpXbEpXZDBWaU5ubzJjRlkzVjFsbFgwVmlURlpuYnpCUE5HNTBhRFpaVEZrMVFYTjZObkIwWTBVNE4x"
	$string16 = "Vm5CWFFVZG9OamhxZW1OeU5sOTJRV3hZTVROSlpEWTRVM294V1VSUFFFdFdZalE0WlVjeGNsSmtObmhBYURVNFZVZEFjRlZDZGtO"
	$string17 = "Yuii37DWU<<12"
	$string18 = ";while(hdnR9eo3pZ6E3<ZZeD3LjJQ.length){eMImGB"
condition:
	18 of them
}
rule fragus_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(ELI6Q3PZ"
	$string1 = "SnJTbVJqV2tOa09VbGZSMHcwY0ZWZmRrRjBjRFY0Y3psVmNGVjROWGhBV0RZNGJWZzBVa1J4TjNCVlgwVmlhRjkyZURaS1NWOUhj"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "VUpKUVdWS05ISlZjMXBTTUdWRlNFQmpaMjlrVDBCTFYzY3pZbGRpZG5oeldFUndkSE16YjB4M2JXSnFZMWRpZVY4ellreDNaMko1"
	$string4 = "((Yuii37DWU"
	$string5 = "YURVNFZXUlhjRlZDZGxsQVJ6UlNaRTlBUzFkM00ySlhiekU0ZEhnMWNrUjZZM0kyWDNaQmJGZ3hNMGxrTmpoVGVqRlpkSEUyV1dW"
	$string6 = "String.fromCharCode(ZZeD3LjJQ);}else if(QIyZsvvbEmVOpp"
	$string7 = "1);ELI6Q3PZ"
	$string8 = "));Yuii37DWU"
	$string9 = ");CUer0x"
	$string10 = "T1ZaQ05IUkRTVGhqT1VWd1ZWOUpRMlZLZG5oNlQwQkxWM2N6WWxkQmRrRkFPVmR3VlRsYWJsWnNOWGhKT1ZkeFZWazFRbEU1UlZK"
	$string11 = "TlpkM2wxS3lzcExUUTRYU2s4UEhocFVqRk9jazA3SUdsbUtIaHBVakZPY2swcGV5QkdWek5NVnlzOVVrSklWVE0wVDJ0NlpTZzJP"
	$string12 = "String.fromCharCode(((eMImGB"
	$string13 = "RGRDUkV0WFV6VkJkRkV4WHpCalYwRkhhRFk0YW5wamNqWmZka0ZzV0RaSWExZzBXWEZDUlZsQVpEWkJOMEoyZUhwd1duSlRXVE5J"
	$string14 = "SCpMaWXOuME(mi1mm8bu87rL0W);eval(Pcii3iVk1AG);</script></body></html>"
	$string15 = "Yuii37DWU"
	$string16 = "Yuii37DWU<<12"
	$string17 = "eTVzWlc1bmRHZ3NJRWhWUnpWRlJuRkZSRVUwUFRFd01qUXNJR2hQVlZsRVJFVmxVaXdnZUVKU1FscE1ORzF3Y21SMGJpd2dSbGN6"
condition:
	17 of them
}
rule fragus_js_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "377431417b34de8592afecaea9aab95d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.appendChild(bdy);try{for (i"
	$string1 = "0; i<10; i"
	$string2 = "default"
	$string3 = "var m "
	$string4 = "/g, document.getElementById('divid').innerHTML));"
	$string5 = " n.substring(0,r/2);"
	$string6 = "document.getElementById('f').innerHTML"
	$string7 = "'atk' onclick"
	$string8 = "function MAKEHEAP()"
	$string9 = "document.createElement('div');"
	$string10 = "<button id"
	$string11 = "/g, document.getElementById('divid').innerHTML);"
	$string12 = "document.body.appendChild(gg);"
	$string13 = "var bdy "
	$string14 = "var gg"
	$string15 = " unescape(gg);while(n.length<r/2) { n"
condition:
	15 of them
}
rule fragus_js_java
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "7398e435e68a2fa31607518befef30fb"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "I></XML><SPAN DATASRC"
	$string1 = "setTimeout('vparivatel()',8000);function vparivatel(){document.write('<iframe src"
	$string2 = "I DATAFLD"
	$string3 = " unescape("
	$string4 = ", 1);swf.setAttribute("
	$string5 = "function XMLNEW(){var spray "
	$string6 = "vparivatel.php"
	$string7 = "6) ){if ( (lv"
	$string8 = "'WIN 9,0,16,0')"
	$string9 = "d:/Program Files/Outlook Express/WAB.EXE"
	$string10 = "<XML ID"
	$string11 = "new ActiveXObject("
	$string12 = "'7.1.0') ){SHOWPDF('iepdf.php"
	$string13 = "function SWF(){try{sv"
	$string14 = "'WIN 9,0,28,0')"
	$string15 = "C DATAFORMATAS"
	$string16 = " shellcode;xmlcode "
	$string17 = "function SNAPSHOT(){var a"
condition:
	17 of them
}
rule fragus_js_quicktime
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "6bfc7bb877e1a79be24bd9563c768ffd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "                setTimeout("
	$string1 = "wnd.location"
	$string2 = "window;"
	$string3 = "        var pls "
	$string4 = "        mem_flag "
	$string5 = ", 1500);} else{ PRyyt4O3wvgz(1);}"
	$string6 = "         } catch(e) { }"
	$string7 = " mem_flag) JP7RXLyEu();"
	$string8 = " 0x400000;"
	$string9 = "----------------------------------------------------------------------------------------------------"
	$string10 = "        heapBlocks "
	$string11 = "        return mm;"
	$string12 = "0x38);"
	$string13 = "        h();"
	$string14 = " getb(b,bSize);"
	$string15 = "getfile.php"
condition:
	15 of them
}
rule fragus_js_vml
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "8ab72337c815e0505fcfbc97686c3562"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " 0x100000;"
	$string1 = "            var gg "
	$string2 = "/g, document.getElementById('divid').innerHTML));"
	$string3 = "                                var sss "
	$string4 = "                }"
	$string5 = "                        document.body.appendChild(obj);"
	$string6 = "                                var hbs "
	$string7 = " shcode; }"
	$string8 = " '<div id"
	$string9 = " hbs - (shcode.length"
	$string10 = "){ m[i] "
	$string11 = " unescape(gg);"
	$string12 = "                                var z "
	$string13 = "                                var hb "
	$string14 = " Math.ceil('0'"
condition:
	14 of them
}
rule Fusion
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
}rule Gandcrab
{
    meta:
        author = "kevoreilly"
        description = "Gandcrab Payload"
        cape_type = "Gandcrab Payload"
    strings:
        $string1 = "GDCB-DECRYPT.txt" wide
        $string2 = "GandCrabGandCrabnomoreransom.coinomoreransom.bit"
        $string3 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" wide
        $string4 = "KRAB-DECRYPT.txt" wide
    condition:
        uint16(0) == 0x5A4D and any of ($string*)
}
rule Ganelp
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

rule Gazer_certificate_subject {
  meta:
    author      = "ESET Research"
    date        = "2017-08-30"
    description = "Turla Gazer malware"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

condition:
    for any i in (0..pe.number_of_signatures - 1):
        (pe.signatures[i].subject contains "Solid Loop" or pe.signatures[i].subject contains "Ultimate Computer Support")
}

rule Gazer_certificate
{
  meta:
    author      = "ESET Research"
    date        = "2017-08-30"
    description = "Turla Gazer malware"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

  strings:
    $certif1 = {52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02}
    $certif2 = {12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c}

  condition:
    (uint16(0) == 0x5a4d) and 1 of them and filesize < 2MB
}

rule Gazer_logfile_name
{
  meta:
    author      = "ESET Research"
    date        = "2017-08-30"
    description = "Turla Gazer malware"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

  strings:
    $s1 = "CVRG72B5.tmp.cvr"
    $s2 = "CVRG1A6B.tmp.cvr"
    $s3 = "CVRG38D9.tmp.cvr"

  condition:
    (uint16(0) == 0x5a4d) and 1 of them
}
rule Generic_Phishing_PDF
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
}rule GetTickCountAntiVM
{
    meta:
        author = "kevoreilly"
        description = "GetTickCountAntiVM bypass"
        cape_options = "bp0=$antivm1-13,bp0=$antivm5-40,bp0=$antivm6,action0=wret,hc0=1,bp1=$antivm2-6,action1=wret,hc1=1,count=1,bp2=$antivm3+42,action2=jmp:96,bp3=$antivm4-9,action3=wret,hc3=1"
        hash = "662bc7839ed7ddd82d5fdafa29fafd9a9ec299c28820fe4104fbba9be1a09c42"
        hash = "00f1537b13933762e1146e41f3bac668123fac7eacd0aa1f7be0aa37a91ef3ce"
        hash = "549bca48d0bac94b6a1e6eb36647cd007fed5c0e75a0e4aa315ceabdafe46541"
        hash = "90c29a66209be554dfbd2740f6a54d12616da35d0e5e4af97eb2376b9d053457"
    strings:
        $antivm1 = {57 FF D6 FF D6 BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm2 = {F2 0F 11 45 ?? FF 15 [4] 6A 00 68 10 27 00 00 52 50 E8 [4] 8B C8 E8 [4] F2 0F 59 45}
        $antivm3 = {0F 57 C0 E8 [4] 8B 35 [4] BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm4 = {F2 0F 11 45 EC FF 15 [4] 8B DA 8B C8 BA [4] 89 5D FC F7 E2 BF [4] 89 45 F4 8B F2 8B C1 B9}
        $antivm5 = {BB 01 00 00 00 8B FB 90 FF 15 [4] FF C7 66 0F 6E C7 F3 0F E6 C0 66 0F 2F F8 73 EA}
        $antivm6 = {48 81 EC 88 00 00 00 0F 57 C0 F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11}
    condition:
        any of them
}
import "pe"

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
}rule Gootkit
{
    meta:
        author = "kevoreilly"
        description = "Gootkit Payload"
        cape_type = "Gootkit Payload"
    strings:
        $code1 = {C7 45 ?? ?? ?? 4? 00 C7 45 ?? ?? 10 40 00 C7 45 E? D8 ?? ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 [1-2] 00 10 40 00 89 [5-6] 43 00 89 ?? ?? 68 E8 80 00 00 FF 15}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule GootLoader_Dotnet
{
    meta:
        id = "3b73JCHd13eRtWf0DUe0ko"
        fingerprint = "2cba1239f67959e2601296cfcdcb8afa29db2c36f4c449424aa17f882f5e949a"
        version = "1.0"
	creation_date = "2022-07-20"
        first_imported = "2022-07-20"
        last_modified = "2022-07-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies GootLoader, Dotnet variant."
        category = "MALWARE"
        malware = "GOOTLOADER"
        reference = "https://blog.nviso.eu/2022/07/20/analysis-of-a-trojanized-jquery-script-gootloader-unleashed/"

strings:

	$ = { 15 00 00 0a 6f 16 00 00 0a 0d ?? ?? ?? ?? 00 00 de 00 00 09 6f 09 00 00 0a 16 fe 01 16 fe 01 13 09 11 09 2d 03 00 2b 
	1d 00 07 09 28 12 00 00 0a 0b 00 00 08 17 58 0c 08 20 9f 86 01 00 fe 04 13 09 11 09 2d ?? ?? ?? ?? 00 00 0a 00 07 72 ?? 00 00 70 ?? 3b 00 00 70 6f  }
	
	$ = {73 1D 00 00 06 0A 06 02 7D 6A 00 00 04 00 16 06 7B 6A 00 00 04 6F 09 00 00 0A 28 0A 00 00 0A 7E 01 00 00 04 2D 
	13 14 FE 06 03 00 00 06 73 0B 00 00 0A 80 01 00 00 04 2B 00 7E 01 00 00 04 28 01 00 00 2B 06 FE 06 1E 00 00 06 73 0D 
	00 00 0A 28 02 00 00 2B 28 03 00 00 2B 0B 2B 00 07 2A }


condition:
	any of them
}
rule GuloaderB
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2021 Edition"
        cape_options = "bp0=$trap0,action0=ret,bp1=$trap1,action1=ret:2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,bp3=$trap2+7,action3=skip"
        packed = "9ec05fd611c2df63c12cc15df8e87e411f358b7a6747a44d4a320c01e3367ca8"
    strings:
        $trap0 = {81 C6 00 10 00 00 [0-88] 81 FE 00 F0 [2] 0F 84 [2] 00 00}
        $trap1 = {31 FF [0-128] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-360] 83 F9 18 [0-460] FF E3}
        $trap2 = {83 BD 9C 00 00 00 00 0F 85 [2] 00 00}
    condition:
        3 of them
}

rule GuloaderPrecursor
{
    meta:
        author = "kevoreilly"
        description = "Guloader precursor"
        cape_options = "bp0=$antidbg,action0=scan,hc0=1,count=0"
    strings:
        $antidbg = {39 48 04 (0F 85 [3] ??|75 ??) 39 48 08 (0F 85 [3] ??|75 ??) 39 48 0C (0F 85 [3] ??|75 ??)}
        $except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
    condition:
        2 of them and not uint16(0) == 0x5A4D
}

rule GuloaderC
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2023 Edition"
        cape_options = "clear,bp0=$trap0,bp0=$trap0A,hc0=0,action0=ret,bp1=$trap1,action1=ret:4,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0"
        packed = "d0c1e946f02503a290d24637b5c522145f58372a9ded9e647d24cd904552d235"
        packed = "26760a2ef432470c7fd2d570746b7decdcf34414045906871f33d80ff4dfc6ba"
    strings:
        $antidbg = {39 48 04 0F 85 [4] 39 48 08 0F 85 [4] 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [4] 39 48 18 0F 85}
        $except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
        $trap0 = {81 C6 00 10 00 00 [0-148] (39 CE|3B B5) [0-6] 0F 84 [2] 00 00}
        $trap0A = {E8 00 00 00 00 59 [0-2800] 81 C6 00 10 00 00 [0-148] (39 CE|3B B5) [0-6] 0F 84 [2] 00 00}
        $trap1 = {89 D6 60 0F 31 B8 [4] (05|35|2D|B8) [4] (05|35|2D|B8) [4] (05|35|2D|B8) [4] 0F A2}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-800] FF E3}
    condition:
        3 of them
}
rule Hancitor
{
    meta:
        author = "threathive"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
       $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
       $fmt_string2 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
       $ipfy = "http://api.ipify.org"
       $user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule HeavensGate
{
    meta:
        author = "kevoreilly"
        description = "Heaven's Gate: Switch from 32-bit to 64-mode"
        cape_type = "Heaven's Gate"

    strings:
        $gate_v1 = {6A 33 E8 00 00 00 00 83 04 24 05 CB}
        $gate_v2 = {9A 00 00 00 00 33 00 89 EC 5D C3 48 83 EC 20 E8 00 00 00 00 48 83 C4 20 CB}
        $gate_v3 = {5A 66 BB 33 00 66 53 50 89 E0 83 C4 06 FF 28}

    condition:
        ($gate_v1 or $gate_v2 or $gate_v3)
}
rule HeavensSyscall
{
    meta:
        author = "kevoreilly"
        description = "Bypass variants of heaven's gate direct syscalls"
        cape_options = "clear,br0=$gate1-9,action1=seteax:0,count=0,sysbp=$sysenter+10"
        packed = "2950b4131886e06bdb83ab1611b71273df23b0d31a4d8eb6baddd33327d87ffa"
    strings:
        $gate1 = {00 00 00 00 74 24 8D 45 F8 50 6A FF FF 95 [4] 85 C0 74 08 8B 4D F8 89 4D FC EB 07 C7 45 FC 00 00 00 00 8B 45 FC EB 02 33 C0 8B E5 5D C2 C0}
        $sysenter = {68 [4] E8 [4] E8 [4] C2 ?? 00 CC CC CC CC CC CC CC CC}
    condition:
        uint16(0) == 0x8B55 and all of them
}
rule Hermes
{
    meta:
        author = "kevoreilly"
        description = "Hermes Payload"
        cape_type = "Hermes Payload"
    strings:
        $ext = ".HRM" wide
        $vss = "vssadmin Delete"
        $email = "supportdecrypt@firemail.cc" wide
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
rule Hidden
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
}rule IcedIDSyscallWriteMem
{
    meta:
        author = "kevoreilly"
        description = "IcedID 'syscall' packer bypass - direct write variant"
        cape_options = "bp0=$tokencheck+9,action0=jmp,count=0"
        packed = "28075ecae5e224c06e250f2c949c826b81844bca421e9158a7a9e965a29ef894"
        packed = "045dff9f14a03225df55997cb2ca74ff60ecaf317b9e033ea93386785db84161"
    strings:
        $tokencheck = {39 5D ?? 75 06 83 7D ?? 03 74 05 BB 01 00 00 00 41 89 1C ?? 48 8B 4D ?? 41 FF D?}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDHook
{
    meta:
        author = "kevoreilly"
        description = "IcedID hook fix"
        cape_options = "ntdll-protect=0"
    strings:
        $hook = {C6 06 E9 83 E8 05 89 46 01 8D 45 ?? 50 FF 75 ?? 6A 05 56 6A FF E8 2D FA FF FF}
    condition:
        any of them
}

rule IcedIDPackerA
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "fbad60002286599ca06d0ecb3624740efbf13ee5fda545341b3e0bf4d5348cfe"
    strings:
        $init = "init"
        $export = {48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 81 EC [2] 00 00 41 8B E9 49 8B F0 48 8B FA 48 8B D9}
        $alloc = {8B 50 50 33 C9 44 8D 49 40 41 B8 00 30 00 00 FF 15 [4] 48 89 44 24 28 [0-3] 48 89 84 24 ?? 00 00 00 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerB
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "6517ef2c579002ec62ddeb01a3175917c75d79ceca355c415a4462922c715cb6"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 4C 24 08 41 55 41 56 41 57 48 81 EC ?? 00 00 00 B9 [2] 00 00 4C 8B EA E8}
        $loop = {8B C2 48 8D 49 01 83 E0 07 FF C2 0F B6 44 30 ?? 30 41 FF 3B D5 72}
        //$load = {41 FF D7 33 D2 41 B8 00 80 00 00 49 8B CF FF 54}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerC
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "c06805b6efd482c1a671ec60c1469e47772c8937ec0496f74e987276fa9020a5"
        hash = "265c1857ac7c20432f36e3967511f1be0b84b1c52e4867889e367c0b5828a844"
    strings:
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 3A ED 74}
        $alloc = {41 B8 00 10 00 00 8B D0 33 C9 66 3B ?? (74|0F 84)}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerD
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "7b226f8cc05fa7d846c52eb0ec386ab37f9bae04372372509daa6bacc9f885d8"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 66 3B ED 74}
        $load = {41 B8 00 80 00 00 33 D2 48 8B 4C [2] EB ?? B9 69 04 00 00 E8 [4] 48 89 84 [2] 00 00 00 66 3B ED 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedSleep
{
    meta:
        author = "kevoreilly"
        description = "IcedID sleep bypass"
        cape_options = "force-sleepskip=1"
        packed = "e99f3517a36a9f7a55335699cfb4d84d08b042d47146119156f7f3bab580b4d7"
    strings:
        $sleep = {89 4C 24 08 48 83 EC 38 8B 44 24 40 48 69 C0 10 27 00 00 48 F7 D8 48 89 44 24 20 48 8D 54 24 20 33 C9 FF 15 [4] 48 83 C4 38 C3}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule IcedIDLoader
{
    meta:
        author = "kevoreilly, threathive, enzo, r0ny123"
        description = "IcedID Loader"
        cape_type = "IcedIDLoader Payload"
    strings:
        $crypt1 = {8A 04 ?? D1 C? F7 D? D1 C? 81 E? 20 01 00 00 D1 C? F7 D? 81 E? 01 91 00 00 32 C? 88}
        $crypt2 = {8B 44 24 04 D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 C3}
        $crypt3 = {41 00 8B C8 C1 E1 08 0F B6 C4 66 33 C8 66 89 4? 24 A1 ?? ?? 41 00 89 4? 20 A0 ?? ?? 41 00 D0 E8 32 4? 32}
        $crypt4 = {0F B6 C8 [0-3] 8B C1 83 E1 0F [0-1] C1 E8 04 [0-1] 0F BE [2-5] 66 [0-1] 89 04 [1-2] 0F BE [2-5] 66 [0-1] 89 44 [2-3] 83 [4-5] 84 C0 75}
        $crypt5 = {48 C1 E8 ?? 0F BE 44 05 ?? 66 89 04 5E 44 88 75 ?? C7 45 [5] C7 45 [5] C7 45 [5] C7 45 [5] 44 89 5D}
        $crypt6 = {0F B6 D2 8B C2 48 C1 E8 04 0F BE 44 [2] 66 41 89 [0-80] 83 E2 0F 49 FF C0 0F BE 44 15 ?? 66 41 89 44}
        $download1 = {8D 44 24 40 50 8D 84 24 44 03 00 00 68 04 21 40 00 50 FF D5 8D 84 24 4C 01 00 00 C7 44 24 28 01 00 00 00 89 44 24 1C 8D 4C 24 1C 8D 84 24 4C 03 00 00 83 C4 0C 89 44 24 14 8B D3 B8 BB 01 00 00 66 89 44 24 18 57}
        $download2 = {8B 75 ?? 8D 4D ?? 8B 7D ?? 8B D6 57 89 1E 89 1F E8 [4] 59 3D C8 00 00 00 75 05 33 C0 40 EB}
        $download3 = {B8 50 00 00 00 66 89 45 ?? 4C 89 65 ?? 4C 89 75 ?? E8 [4] 48 8B 1E 3D 94 01 00 00}
        $major_ver = {0F B6 05 ?? ?? ?? ?? 6A ?? 6A 72 FF 75 0C 6A 70 50 FF 35 ?? ?? ?? ?? 8D 45 80 FF 35 ?? ?? ?? ?? 6A 63 FF 75 08 6A 67 50 FF 75 10 FF 15 ?? ?? ?? ?? 83 C4 38 8B E5 5D C3}
        $decode1 = {4? 8D [5-6] 8A 4? [1-3] 32 }//0? 01 88 44 [2] 4?}
        $decode2 = {42 0F B6 4C 02 ?? 42 0F B6 04 02 32 C8 88 8C 15 ?? ?? ?? ?? 48 FF C2 48 83 FA 20}
    condition:
        2 of them
}
rule IEuser_author_doc
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
        category = "INFO"
        reference = "https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/"


    strings:
        $doc = {D0 CF 11 E0}
        $ieuser = {49 00 45 00 55 00 73 00 65 00 72}

    condition:
        $doc at 0 and $ieuser
}
rule IISRaid
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
rule ISO_exec
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
rule Jaff
{
    meta:
        author = "kevoreilly"
        description = "Jaff Payload"
        cape_type = "Jaff Payload"
    strings:
        $a1 = "CryptGenKey"
        $a2 = "353260540318613681395633061841341670181307185694827316660016508"
        $b1 = "jaff"
        $b2 = "2~1c0q4t7"
    condition:
        uint16(0) == 0x5A4D and (any of ($a*) ) and (1 of ($b*))
}
rule generic_javascript_obfuscation
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "JavaScript Obfuscation Detection"
	sample_filetype = "js-html"
strings:
	$string0 = /eval\(([\s]+)?(unescape|atob)\(/ nocase
	$string1 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?\[([\s]+)?\"\\x[0-9a-fA-F]+/ nocase
	$string2 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?eval;/
condition:
	any of them
}

rule possible_includes_base64_packed_functions  
{ 
	meta: 
		impact = 5 
		hide = true 
		desc = "Detects possible includes and packed functions" 
	strings: 
		$f = /(atob|btoa|;base64|base64,)/ nocase
		//$ff = /(?:[A-Za-z0-9]{4}){2,}(?:[A-Za-z0-9]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9][AQgw]==)/ nocase 
		$fff = /([A-Za-z0-9]{4})*([A-Za-z0-9]{2}==|[A-Za-z0-9]{3}=|[A-Za-z0-9]{4})/ 
	condition: 
		$f and $fff
}
 
rule BeEF_browser_hooked {
	meta:
		description = "Yara rule related to hook.js, BeEF Browser hooking capability"
		author = "Pasquale Stirparo"
		date = "2015-10-07"
		hash1 = "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"
	strings:
		$s0 = "mitb.poisonAnchor" wide ascii
		$s1 = "this.request(this.httpproto" wide ascii
		$s2 = "beef.logger.get_dom_identifier" wide ascii
		$s3 = "return (!!window.opera" wide ascii 
		$s4 = "history.pushState({ Be:\"EF\" }" wide ascii 
		$s5 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/10\\./)" wide ascii 
		$s6 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/11\\./)" wide ascii 
		$s7 = "window.navigator.userAgent.match(/Avant TriCore/)" wide ascii 
		$s8 = "window.navigator.userAgent.match(/Iceweasel" wide ascii 
		$s9 = "mitb.sniff(" wide ascii 
		$s10 = "Method XMLHttpRequest.open override" wide ascii 
		$s11 = ".browser.hasWebSocket" wide ascii 
		$s12 = ".mitb.poisonForm" wide ascii 
		$s13 = "resolved=require.resolve(file,cwd||" wide ascii 
		$s14 = "if (document.domain == domain.replace(/(\\r\\n|\\n|\\r)/gm" wide ascii 
		$s15 = "beef.net.request" wide ascii 
		$s16 = "uagent.search(engineOpera)" wide ascii 
		$s17 = "mitb.sniff" wide ascii
		$s18 = "beef.logger.start" wide ascii
	condition:
		all of them
}

rule src_ptheft_command {
	meta:
		description = "Auto-generated rule - file command.js"
		author = "Pasquale Stirparo"
		reference = "not set"
		date = "2015-10-08"
		hash = "49c0e5400068924ff87729d9e1fece19acbfbd628d085f8df47b21519051b7f3"
	strings:
		$s0 = "var lilogo = 'http://content.linkedin.com/etc/designs/linkedin/katy/global/clientlibs/img/logo.png';" fullword wide ascii /* score: '38.00' */
		$s1 = "dark=document.getElementById('darkenScreenObject'); " fullword wide ascii /* score: '21.00' */
		$s2 = "beef.execute(function() {" fullword wide ascii /* score: '21.00' */
		$s3 = "var logo  = 'http://www.youtube.com/yt/brand/media/image/yt-brand-standard-logo-630px.png';" fullword wide ascii /* score: '32.42' */
		$s4 = "description.text('Enter your Apple ID e-mail address and password');" fullword wide ascii /* score: '28.00' */
		$s5 = "sneakydiv.innerHTML= '<div id=\"edge\" '+edgeborder+'><div id=\"window_container\" '+windowborder+ '><div id=\"title_bar\" ' +ti" wide ascii /* score: '28.00' */
		$s6 = "var logo  = 'https://www.yammer.com/favicon.ico';" fullword wide ascii /* score: '27.42' */
		$s7 = "beef.net.send('<%= @command_url %>', <%= @command_id %>, 'answer='+answer);" fullword wide ascii /* score: '26.00' */
		$s8 = "var title = 'Session Timed Out <img src=\"' + lilogo + '\" align=right height=20 width=70 alt=\"LinkedIn\">';" fullword wide ascii /* score: '24.00' */
		$s9 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=20 width=70 alt=\"YouTube\">';" fullword wide ascii /* score: '24.00' */
		$s10 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=24 width=24 alt=\"Yammer\">';" fullword wide ascii /* score: '24.00' */
		$s11 = "var logobox = 'style=\"border:4px #84ACDD solid;border-radius:7px;height:45px;width:45px;background:#ffffff\"';" fullword wide ascii /* score: '21.00' */
		$s12 = "sneakydiv.innerHTML= '<br><img src=\\''+imgr+'\\' width=\\'80px\\' height\\'80px\\' /><h2>Your session has timed out!</h2><p>For" wide ascii /* score: '23.00' */
		$s13 = "inner.append(title, description, user,password);" fullword wide ascii /* score: '23.00' */
		$s14 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s15 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s16 = "answer = document.getElementById('uname').value+':'+document.getElementById('pass').value;" fullword wide ascii /* score: '22.00' */
		$s17 = "password.keydown(function(event) {" fullword wide ascii /* score: '21.01' */
	condition:
		13 of them
}rule JSSLoader
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
}// Keydnap packer yara rule
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
rule Kovter
{
    meta:
        author = "kevoreilly"
        description = "Kovter Payload"
        cape_type = "Kovter Payload"
    strings:
        $a1 = "chkok"
        $a2 = "k2Tdgo"
        $a3 = "13_13_13"
        $a4 = "Win Server 2008 R2"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule KPortScan
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
}rule Kpot
{
    meta:
        author = "kevoreilly"
        description = "Kpot Stealer"
        cape_type = "Kpot Payload"
    strings:
        $format   = "%s | %s | %s | %s | %s | %s | %s | %d | %s"
        $username = "username:s:"
        $os       = "OS: %S x%d"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
rule Kronos
{
    meta:
        author = "kevoreilly"
        description = "Kronos Payload"
        cape_type = "Kronos Payload"
    strings:
        $a1 = "user_pref(\"network.cookie.cookieBehavior\""
        $a2 = "T0E0H4U0X3A3D4D8"
        $a3 = "wow64cpu.dll" wide
        $a4 = "Kronos" fullword ascii wide
    condition:
        uint16(0) == 0x5A4D and (2 of ($a*))
}
rule Latrodectus
{
    meta:
        author = "kevoreilly"
        description = "Latrodectus export selection"
        cape_options = "export=$export"
        hash = "378d220bc863a527c2bca204daba36f10358e058df49ef088f8b1045604d9d05"
    strings:
        $export = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 30 4C 8B 05 [4] 33 D2 C7 40 [5] 88 50 ?? 49 63 40 3C 42 8B 8C 00 88 00 00 00 85 C9 0F 84}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule LaZagne
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
}// Linux/Moose yara rules
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
rule LNKR_JS_a
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
rule Lockbit
{
    meta:
        author = "kevoreilly"
        description = "Lockbit Payload"
        cape_type = "Lockbit Payload"
    strings:
        $string1 = "/C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 \"%s\" & Del /f /q \"%s\"" wide
        $string2 = "Ransom" ascii wide
        $crypto  = {8B 4D 08 C1 E9 10 0F B6 D1 8B 4D 0C C1 E9 08 0F B6 C9 8B 14 95 [4] 8B 7D FC 33 14 8D [4] 8B CF C1 E9 18 33 14 8D [4] 0F B6 CB 33 14 8D [4] 8B CF 33 10}
        $decode1 = {8A ?4 34 ?C 0? 00 00 8B 8? 24 ?8 0? 00 00 0F BE ?? 0F BE C? 33 ?? 88 ?? 34 ?? 0? 00 00 46 83 FE 0? 72 DD}
        $decode2 = {8A 44 24 ?? 30 44 0C ?? 41 83 F9 ?? 72 F2}
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}
rule Locky
{
    meta:
        author = "kevoreilly"
        description = "Locky Payload"
        cape_type = "Locky Payload"
    strings:
        $string1 = "wallet.dat" wide
        $string2 = "Locky_recover" wide
        $string3 = "opt321" wide
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
rule LokiBot
{
    meta:
        author = "kevoreilly"
        description = "LokiBot Payload"
        cape_type = "LokiBot Payload"
    strings:
        $a1 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW"
        $a2 = "last_compatible_version"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule Lumma
{
    meta:
        author = "kevoreilly"
        description = "Lumma config extraction"
        cape_options = "bp0=$decode+5,action0=string:ebp,count=0,bp1=$patch+8,action1=skip,typestring=Lumma Config"
        packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
    strings:
        $c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
        $decode = {C6 44 05 00 00 83 C4 2C 5E 5F 5B 5D C3}
        $patch = {66 C7 0? 00 00 8B 46 1? C6 00 01 8B}
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule LummaRemap
{
    meta:
        author = "kevoreilly"
        description = "Lumma ntdll-remap bypass"
        cape_options = "ntdll-remap=0"
        packed = "7972cbf2c143cea3f90f4d8a9ed3d39ac13980adfdcf8ff766b574e2bbcef1b4"
    strings:
        $remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}
    condition:
        uint16(0) == 0x5a4d and any of them
}
rule Magniber
{
    meta:
        author = "kevoreilly"
        description = "Magniber Payload"
        cape_type = "Magniber Payload"
    strings:
        $a1 = {8B 55 FC 83 C2 01 89 55 FC 8B 45 FC 3B 45 08 7D 45 6A 01 6A 00 E8 26 FF FF FF 83 C4 08 89 45 F4 83 7D F4 00 75 18 6A 7A 6A 61 E8 11 FF FF FF 83 C4 08 8B 4D FC 8B 55 F8 66 89 04 4A EB 16}
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule maldoc_indirect_function_call_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule maldoc_find_kernel32_base_method_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

rule maldoc_find_kernel32_base_method_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

rule mwi_document: exploitdoc maldoc
{
    meta:
        description = "MWI generated document"
        author = "@Ydklijnsma"
        source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

      strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"

    condition:
        all of them
}

rule macrocheck : maldoc
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/30" 
        Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
 
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}

rule Office_AutoOpen_Macro : maldoc {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 60
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		uint32be(0) == 0xd0cf11e0 and all of ($s*) and filesize < 300000
}

rule Embedded_EXE_Cloaking : maldoc {
    meta:
        description = "Detects an embedded executable in a non-executable file"
        author = "Florian Roth"
        date = "2015/02/27"
        score = 80
    strings:
        $noex_png = { 89 50 4E 47 }
        $noex_pdf = { 25 50 44 46 }
        $noex_rtf = { 7B 5C 72 74 66 31 }
        $noex_jpg = { FF D8 FF E0 }
        $noex_gif = { 47 49 46 38 }
        $mz  = { 4D 5A }
        $a1 = "This program cannot be run in DOS mode"
        $a2 = "This program must be run under Win32"       
    condition:
        (
            ( $noex_png at 0 ) or
            ( $noex_pdf at 0 ) or
            ( $noex_rtf at 0 ) or
            ( $noex_jpg at 0 ) or
            ( $noex_gif at 0 )
        )
        and
        for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}
rule malicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic at 0 and all of ($reg*)
}

rule suspicious_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic at 0 and not $ver
}

rule suspicious_creation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic at 0 and $header and 1 of ($create*)
}

rule suspicious_title : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic at 0 and $header and 1 of ($title*)
}

rule suspicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic at 0 and $header and 1 of ($author*)
}

rule suspicious_producer : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic at 0 and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic at 0 and $header and 1 of ($creator*)
}

rule possible_exploit : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic at 0 and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic at 0 and 1 of ($reg*)
}

rule multiple_filtering : PDF 
{
        meta: 
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.2"
                weight = 3
                
        strings:
                $magic = { 25 50 44 46 }
                $attrib = /\/Filter\s*(\/(ASCIIHexDecode|LZWDecode|ASCII85Decode|FlateDecode|RunLengthDecode)){2}/
				// left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

        condition: 
                $magic at 0 and $attrib
}

rule suspicious_js : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic at 0 and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/F /

	condition:
		$magic at 0 and 3 of ($attrib*)
}

rule suspicious_embed : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic at 0 and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic at 0 and #reg > 5
}

rule invalid_XObject_js : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic at 0 and not $ver and all of ($attrib*)
}

rule invalid_trailer_structure : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic at 0 and not $reg0 and not $reg1
}

rule multiple_versions : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
        description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"		
		weight = 0
		
        strings:
                $magic = { 25 50 44 46 }
                $s0 = "trailer"
                $s1 = "%%EOF"

        condition:
                $magic at 0 and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule JBIG2_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule FlateDecode_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule embed_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic at 0 and $embed and not $ver
}

rule invalid_xref_numbers : PDF
{
        meta:
			author = "Glenn Edwards (@hiddenillusion)"
			version = "0.1"
			description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
			notes = "This can be also be in a stream..."
			weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
                $reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/
        condition:
                $magic at 0 and not $reg0 and not $reg1
}

rule js_splitting : PDF
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic at 0 and $js and 1 of ($s*)
}

rule BlackHole_v2 : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic at 0 and $content
}


rule XDP_embedded_PDF : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
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
        category = "INFO"

    strings:
        $s1 = "window.moveTo -" ascii wide nocase
        $s2 = "window.resizeTo 0" ascii wide nocase
        $x1 = "window.moveTo(-" ascii wide nocase
        $x2 = "window.resizeTo(" ascii wide nocase

    condition:
        ( all of ($s*) or all of ($x*)) and filesize <50KB
}
rule MassLogger
{
    meta:
        author = "kevoreilly"
        description = "MassLogger"
        cape_type = "MassLogger Payload"
    strings:
        $name = "MassLogger"
        $fody = "Costura"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
rule Maze
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
}rule MegaCortex
{
    meta:
        author = "kevoreilly"
        description = "MegaCortex Payload"
        cape_type = "MegaCortex Payload"
    strings:
        $str1 = ".megac0rtx" ascii wide
        $str2 = "vssadmin delete shadows /all" ascii
        $sha256 = {98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule MiniTor
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
}rule ModiLoader {
    meta:
        author = "ditekSHen"
        description = "ModiLoader detonation shim"
        cape_options = "ntdll-protect=0"
    strings:
        $x1 = "*()%@5YT!@#G__T@#$%^&*()__#@$#57$#!@" fullword wide
        $x2 = "dntdll" fullword wide
        $x3 = "USERPROFILE" fullword wide
        $s1 = "%s, ProgID: \"%s\"" ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s3 = "responsetext" ascii
        $s4 = "C:\\Users\\Public\\" ascii
        $s5 = "[InternetShortcut]" fullword ascii
        $c1 = "start /min powershell -WindowStyle Hidden -inputformat none -outputformat none -NonInteractive -Command \"Add-MpPreference -ExclusionPath 'C:\\Users'\" & exit" ascii  nocase
        $c2 = "mkdir \"\\\\?\\C:\\Windows \"" ascii nocase
        $c3 = "mkdir \"\\\\?\\C:\\Windows \\System32\"" ascii nocase
        $c4 = "ECHO F|xcopy \"" ascii nocase
        $c5 = "\"C:\\Windows \\System32\" /K /D /H /Y" ascii nocase
        $c6 = "ping 127.0.0.1 -n 6 > nul" ascii nocase
        $c7 = "del /q \"C:\\Windows \\System32\\*\"" ascii nocase
        $c8 = "rmdir \"C:\\Windows \\System32\"" ascii nocase
        $c9 = "rmdir \"C:\\Windows \"" ascii nocase
        $g1 = "powershell" ascii nocase
        $g2 = "mkdir \"\\\\?\\C:\\" ascii nocase
        $g3 = "\" /K /D /H /Y" ascii nocase
        $g4 = "ping 127.0.0.1 -n" ascii nocase
        $g5 = "del /q \"" ascii nocase
        $g6 = "rmdir \"" ascii nocase
    condition:
        uint16(0) == 0x5a4d and
        (
            (2 of ($x*) and (all of ($g*) or (2 of ($s*) and 2 of ($c*)))) or
            (all of ($s*) and (2 of ($c*) or all of ($g*))) or
            (4 of ($c*) and (1 of ($x*) or 2 of ($s*))) or
            (all of ($g*) and 4 of ($c*)) or
            13 of them
        )         
}
rule Mole
{
    meta:
        author = "kevoreilly"
        description = "Mole Payload"
        cape_type = "Mole Payload"
    strings:
        $a1 = ".mole0" wide
        $a2 = "_HELP_INSTRUCTION.TXT" wide
        $a3 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule Monero_Compromise
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
}rule MortisLocker
{
	meta:
		author = "ANY.RUN"
		description = "Detects MortisLocker ransomware"
		date = "2023-10-05"
		reference = "https://twitter.com/MalGamy12/status/1709475837685256466"
		hash1 = "a5012e20342f4751360fd0d15ab013385cecd2a5f3e7a3e8503b1852d8499819"
		hash2 = "b6a4331334a16af65c5e4193f45b17c874e3eff8dd8667fd7cb8c7a570e2a8b9"
		hash3 = "c6df9cb7c26e0199106bdcd765d5b93436f373900b26f23dfc03b8b645c6913f"
		hash4 = "dac667cfc7824fd45f511bba83ffbdb28fa69cdeff0909979de84064ca2e0283"
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

		$log_bcrypt = /BCrypt[\w]+ failed with error code:/ fullword ascii
		$log_drive_1 = "[i] Encrypting Logical Drives:" fullword ascii
		$log_drive_2 = "[-] No drives found." fullword ascii
		$log_share_1 = "[i] Encrypting Network Shares:" fullword ascii
		$log_share_2 = "[!] Failed to enumerate network shares:" fullword ascii
		$log_share_3 = "[-] No network shares found." fullword ascii
		$log_file_1 = "Encryption failed for file:" fullword ascii
		$log_file_2 = "Encryption successful. Encrypted file:" fullword ascii
		$log_file_3 = "Failed to open output file:" fullword ascii
		$log_file_4 = "Failed to rename file:" fullword ascii
		$log_file_5 = "File is empty:" fullword ascii
		$log_rbin_1 = "[+] Emptied Recycle Bin." fullword ascii
		$log_rbin_2 = "Recycle Bin emptied successfully." fullword ascii
		$log_rbin_3 = "[!] Failed to Empty Recycle Bin." fullword ascii
		$log_rbin_4 = "Failed to empty Recycle Bin." fullword ascii
		$log_priv_1 = "[+] Enabled Privileges." fullword ascii
		$log_priv_2 = "[!] Failed to enable privileges." fullword ascii
		$log_aes_1 = "[*] AES Key:" fullword ascii
		$log_aes_2 = "[i] AES Key:" fullword ascii
		$log_aes_3 = "[!] Failed to generate AES Key." fullword ascii
		$log_folder = "[*] Ignored Folder:" fullword ascii
		$log_lock = "[+] Locked:" fullword ascii
		$log_msg_1 = "cryptDir execution time:" fullword ascii
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
}rule MysterySnail
{
    meta:
        author = "kevoreilly"
        description = "MysterySnail anti-sandbox bypass"
        cape_options = "bp0=$anti+62,action0=skip,count=0"
    strings:
        $anti = {F2 0F 10 [3] 66 0F 2F 05 [4] 76 0A 8B [3] FF C0 89 [3] B9 5B 05 00 00 FF 15 [4] E8 [4] 89 [3] 8B [3] 8B [3] 2B C8 8B C1 3B [3] 7E 16}
    condition:
        any of them
}
rule NagogyGrabber {
    meta:
        author = "Any.RUN"
        reference = "https://twitter.com/MalGamy12/status/1698367753919357255"
        description = "Detects Nagogy Grabber"
        date = "2023-04-04"

        hash1 = "1518a876c87c9189c2fcb29a524aa11bfdc7e6e5d0cac9cc40cd0af1b96b34ae"
        hash2 = "1e828b39b97fa746b4efcb4ceb35c03cabc6134e7d4e3a3cf96e572ddbd465b1"
        hash3 = "28569be03334e7c36e560c9a5a5f18ee3e952274475a8bd00f60c11b2abc4368"
        hash4 = "53fe973fd9a5be2154cf2d21344f3698a192ab238b11995aba8da6ccf9e26f32"
        hash5 = "81f575f131240ba1f4eeabfb721e6e45ef3a560473fe2ac5e9e4917dcc7bf785"
        hash6 = "b41e7a3da1d450dc770072a5c2761af441509e17b7fb704d86fb0049fdade071"
        hash7 = "c78835281b827762c4df1b3d771f81b091743f6d49db03766cc911ddc970586a"

    strings:
        //  _ __   __ _  __ _  ___   __ _ _   _
        // | '_ \ / _` |/ _` |/ _ \ / _` | | | |
        // | | | | (_| | (_| | (_) | (_| | |_| |
        // |_| |_|\__,_|\__, |\___/ \__, |\__, |
        //              |___/       |___/ |___/
        //                  _     _
        //   __ _ _ __ __ _| |__ | |__   ___ _ __
        //  / _` | '__/ _` | '_ \| '_ \ / _ \ '__|
        // | (_| | | | (_| | |_) | |_) |  __/ |
        //  \__, |_|  \__,_|_.__/|_.__/ \___|_|
        //  |___/
        $x1 = {
            20 00 20 00 5f 00 20 00 5f 00 5f 00 20 00 20 00 20 00 5f 00 5f 00
            20 00 5f 00 20 00 20 00 5f 00 5f 00 20 00 5f 00 20 00 20 00 5f 00
            5f 00 5f 00 20 00 20 00 20 00 5f 00 5f 00 20 00 5f 00 20 00 5f 00
            20 00 20 00 20 00 5f 00 20 00 20 00 20 00 0a
        }

        $x2 = "Nagogy grabber - DreamyOak" fullword ascii

        $s1 = "https://discord.com/api/v6/auth/login" fullword ascii
        $s2 = "httpdebuggerui.exe" fullword ascii
        $s3 = "df5serv.exe" fullword ascii
        $s4 = "qemu-ga.exe" fullword ascii
        $s5 = "joeboxcontrol.exe" fullword ascii
        $s6 = "ksdumper.exe" fullword ascii
        $s7 = "SELECT origin_url, action_url, username_value, password_value, date_created, times_used FROM logins" fullword ascii
        $s8 = "Action URL: " fullword ascii
        $s9 = "D:\\NT3X" fullword ascii
        $s10 = "wmic csproduct get uuid" fullword ascii
        $s11 = "====================IP INFO====================" fullword wide

    condition:
        (uint16(0) == 0x5a4d and 1 of ($x*) and filesize < 20MB) or all of ($s*)
}
rule NanoLocker
{
    meta:
        author = "kevoreilly"
        description = "NanoLocker Payload"
        cape_type = "NanoLocker Payload"
    strings:
        $a1 = "NanoLocker"
        $a2 = "$humanDeadline"
        $a3 = "Decryptor.lnk"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule Nemty
{
    meta:
        author = "kevoreilly"
        description = "Nemty Ransomware Payload"
        cape_type = "Nemty Payload"
    strings:
        $tordir = "TorDir"
        $decrypt = "DECRYPT.txt"
        $nemty = "NEMTY"
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule NetTraveler
{
    meta:
        author = "kevoreilly"
        description = "NetTraveler Payload"
        cape_type = "NetTraveler Payload"
    strings:
        $string1 = {4E 61 6D 65 3A 09 25 73 0D 0A 54 79 70 65 3A 09 25 73 0D 0A 53 65 72 76 65 72 3A 09 25 73 0D 0A} // "Name: %s  Type: %s  Server: %s "
        $string2 = "Password Expiried Time:"
        $string3 = "Memory: Total:%dMB,Left:%dMB (for %.2f%s)"

    condition:
        uint16(0) == 0x5A4D and all of them
}
import "pe"

rule Nighthawk
{
    meta:
        author = "Nikhil Ashok Hegde <@ka1do9>"
        description = "NightHawk C2"
        cape_type = "Nighthawk Payload"

    strings:
        // Not wildcarding register to have better yara performance
        $keying_methods = { 85 C9 74 43 83 E9 01 74 1C 83 F9 01 0F 85 }

        // AES-128 CBC sbox and inverse-sbox used in key expansion
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 }
        $aes_inv_sbox = { 52 09 6A D5 30 36 A5 38 BF }

    condition:
        pe.is_pe and
        // Nighthawk DLL is known to contain a ".profile" section which
        // contains config
        for any s in pe.sections: (s.name == ".profile") and
        all of them
}
rule NLBrute
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
}rule NSIS
{
    meta:
        author = "kevoreilly"
        description = "NSIS Integrity Check function"
        cape_options = "exclude-apis=LdrLoadDll"
        hash = "d0c1e946f02503a290d24637b5c522145f58372a9ded9e647d24cd904552d235"
    strings:
        $check = {6A 1C 8D 45 [3-8] E8 [4] 8B 45 ?? A9 F0 FF FF FF 75 ?? 81 7D ?? EF BE AD DE 75 ?? 81 7D ?? 49 6E 73 74 75 ?? 81 7D ?? 73 6F 66 74 75 ?? 81 7D ?? 4E 75 6C 6C 75 ?? 09 45 08 8B 45 08 8B 0D [4] 83 E0 02 09 05 [4] 8B 45 ?? 3B C6 89 0D [4] 0F 8? [2] 00 00 F6 45 08 08 75 06 F6 45 08 04 75}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule oAuth_Phishing_PDF
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
rule Origin {
    meta:
        author = "kevoreilly"
        description = "Origin Logger payload"
        cape_type = "Origin Payload"
        hash = "ee8a244c904756bdc3987fefc844596774437bcc50d4022ddcc94e957cab6a11"
    strings:
        $s1 = "set_RequestPluginName" fullword ascii
        $s2 = "set_IsCreated" fullword ascii
        $s3 = "set_AllowAutoRedirect" fullword ascii
        $s4 = "set_Antivirus" fullword ascii
        $s5 = "set_MaximumAutomaticRedirections" fullword ascii
        $s6 = "set_ClientId" fullword ascii
        $s7 = "set_SysInfo" fullword ascii
        $s8 = "set_ServerCertificateValidationCallback" fullword ascii
        $s9 = "set_CommandType" fullword ascii
        $s10 = "set_TenantId" fullword ascii
        $s11 = "set_KeepAlive" fullword ascii

        $c1 = {03 16 32 0B 03 2C 08 02 6F 49 00 00 0A 2D 06}
        $c2 = {20 F0 0F 00 00 28 ?? 00 00 0A 7E ?? 00 00 04 2D 11 14 FE}
        $c3 = {06 20 20 4E 00 00 6F ?? 00 00 0A 06 17 6F ?? 00 00 0A 06 1F 32 6F}
        $c4 = {20 00 01 00 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0A 72 ?? 05 00 70 28 ?? 00 00 0A 0A 12 00 28}

        $m1 = "OriginBotnet" ascii
        $m2 = "UpdateBotRequest" ascii
        $m3 = "<Deserialize>b__0" ascii
    condition:
        (uint16(0) == 0x5a4d and ((6 of ($s*) and 2 of ($c*)))) or (2 of ($m*))
}
rule Oyster
{
    meta:
        author = "enzok"
        description = "Oyster Payload"
        cape_type = "Oyster Payload"
        hash = "8bae0fa9f589cd434a689eebd7a1fde949cc09e6a65e1b56bb620998246a1650"
    strings:
		$start_exit = {05 00 00 00 2E 96 1E A6}
		$content_type = {F6 CE 56 F4 76 F6 96 2E 86 C6 96 36 0E 0E 86 04 5C A6 0E 9E 2A B4 2E 76 A6 2E 76 F6 C2}
        $domain = {44 5C 44 76 96 86 B6 F6 26 44 34 44}
        $id = {44 5C 44 64 96 44 DE}
        $ip_local = {44 5C 44 36 86 C6 F6 36 FA 0E 96 44 34 44}
        $table_part_1 = {00 80 40 C0 20 A0 60 E0 10 90 50 D0 30 B0 70 F0 08 88 48 C8 28 A8 68}
        $table_part_2 = {97 57 D7 37 B7 77 F7 0F 8F 4F CF 2F AF 6F EF 1F 9F 5F DF 3F BF 7F FF}
		$decode = {0F B6 0? 8D ?? FF 8A [2] 0F B6 80 [4] 88 04 ?? 46 0F B6 C? 0F B6 80 [4] 88 4? 01 3B F7}
    condition:
        4 of them
}
rule Pafish
{
    meta:
        author = "kevoreilly"
        description = "Pafish bypass"
        cape_options = "bp0=$rdtsc_vmexit_32-2,bp1=$rdtsc_vmexit_32-2,bp0=$rdtsc_vmexit_64+36,bp1=$rdtsc_vmexit_64+36,action0=skip,action1=skip,count=1"
        hash = "9e7d694ed87ae95f9c25af5f3a5cea76188cd7c1c91ce49c92e25585f232d98e"
        hash = "ff24b9da6cddd77f8c19169134eb054130567825eee1008b5a32244e1028e76f"
    strings:
        $rdtsc_vmexit_32 = {8B 45 E8 80 F4 00 89 C? 8B 45 EC 80 F4 00 89 C? 89 F? 09 ?? 85 C0 75 07}
        $rdtsc_vmexit_64 = {48 8B 45 F0 48 BA CD CC CC CC CC CC CC CC 48 F7 E2 48 89 D0 48 C1 E8 03 48 89 45 F0 48 81 7D F0 ?? 0? 00 00 77 07}
    condition:
        uint16(0) == 0x5A4D and any of them
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
}rule PetrWrap
{
    meta:
        author = "kevoreilly"
        description = "PetrWrap Payload"
        cape_type = "PetrWrap Payload"
    strings:
        $a1 = "http://petya3jxfp2f7g3i.onion/"
        $a2 = "http://petya3sen7dyko2n.onion"

        $b1 = "http://mischapuk6hyrn72.onion/"
        $b2 = "http://mischa5xyix2mrhd.onion/"
    condition:
        uint16(0) == 0x5A4D and (any of ($a*)) and (any of ($b*))
}
rule Petya
{
    meta:
        author = "kevoreilly"
        description = "Petya Payload"
        cape_type = "Petya Payload"
    strings:
        $a1 = "CHKDSK is repairing sector"
        $a2 = "wowsmith123456@posteo.net"
        $a3 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
rule phoenix_html
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "8395f08f1371eb7b2a2e131b92037f9a"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string1 = "'></applet><body id"
	$string2 = "<applet mayscript"
	$string3 = "/gmi,String.fromCharCode(2"
	$string4 = "/gmi,' ').replace(/"
	$string5 = "pe;i;;.j1s->c"
	$string6 = "es4Det"
	$string7 = "<textarea>function"
        $string8 = ".replace(/"
	$string9 = ".jar' code"
	$string10 = ";iFc;ft'b)h{s"
condition:
	10 of them
}
rule phoenix_html10
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "f5f8dceca74a50076070f2593e82ec43"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "pae>crAeahoilL"
	$string1 = "D11C0002C0069733E60656F6462070D000402DFF200696E"
	$string2 = "nbte)bbn"
	$string3 = "v9o16,0')0B80002328203;)82F00223A216ifA160A262A462(a"
	$string4 = "0442DFD2E30EC80E42D2E00AC3F3D53C9CAEBFF7E1E805080B044057CB1C0EF7F263DC64E0CBE47C2A21E370EE4A"
	$string5 = ";)npeits0e.uvr;][tvr"
	$string6 = "433EBE90242003E00C606D04036563435805000102000v020E656wa.i118,0',9F902F282620''C62022646660}{A780232A"
	$string7 = "350;var ysjzyq"
	$string8 = "aSmd'lm/t/im.}d.-Ljg,l-"
	$string9 = "0017687F6164706E6967060002008101'2176045ckb"
	$string10 = "63(dcma)nenn869"
	$string11 = "').replace(/"
	$string12 = "xd'c0lrls09sare"
	$string13 = "(]t.(7u(<p"
	$string14 = "d{et;bdBcriYtc:eayF20'F62;23C4AABA3B84FE21C2B0B066C0038B8353AF5C0B4DF8FF43E85FB6F05CEC4080236F3CDE6E"
	$string15 = "/var another;</textarea>"
	$string16 = "Fa527496C62eShHmar(bA,pPec"
	$string17 = "FaA244A676C,150e62A5B2B61,'2F"
condition:
	17 of them
}
rule phoenix_html11
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "be8c81288f9650e205ed13f3167ce256"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "D'0009F0C6941617C43427A76080001000F47020C606volv99,0,6,"
	$string1 = "';)nWd"
	$string2 = "IW'eeCn)s.a9e;0CF300FF379011078E047873754163636960496270486264416455747D69737812060209011301010104D0"
	$string3 = "D8D51F5100019006D60667F2E056940170E01010747"
	$string4 = "515F2F436WemBh2A4560683aFanoi(utse.o1/f;pistelzi"
	$string5 = "/p(e/oah)FHw'aaarDsnwi-"
	$string6 = "COa506u%db10u%1057u%f850u%f500u%0683u%05a8u%0030u%0706u%d300u%585du%38d0u%0080u%5612u'u%A2DdF6u%1M:."
	$string7 = "S(yt)Dj"
	$string8 = "FaA26285325,150e8292A6968,'2F"
	$string9 = "0200e{b<0:D>r5d4u%c005u%0028u%251eu%a095u%6028u%0028u%2500u%f7f7u%70d7u%2025u%9008u%08f8u%c607usu%37"
	$string10 = "(mEtlltopo{{e"
	$string11 = "aSmd'lm/t/im.}d.-Ljg,l-"
	$string12 = "r)C4snfapfuo}"
	$string13 = "').replace(/"
	$string14 = "A282A5ifA160F2628206(a"
	$string15 = "obn0cf"
	$string16 = "d(i'C)rtr.'pvif)iv1ilW)S((Ltl.)2,0,9;0se"
	$string17 = "E23s3003476B18703C179396D08B841BC554F11678F0FEB9505FB355E044F33A540F61743738327E32D97D070FA37D87s000"
	$string18 = "603742E545904575'294E20680,6F902E292A60''E6202A4E6468},e))tep"
condition:
	18 of them
}
rule phoenix_html2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "2fd263f5d988a92715f4146a0006cb31"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Pec.lilsD)E)i-gonP(mgge.eOmn"
	$string1 = "(trt;oo"
	$string2 = "aceeC:0h"
	$string3 = "Vubb.oec.n)a."
	$string4 = "t;o{(bspd}ci:0OO[g(cfjdh}1sN}ntnrlt;0pwf{-"
	$string5 = "seierb)gMle(}ev;is{(b;ga"
	$string6 = "e)}ift"
	$string7 = "Dud{rt"
	$string8 = "blecroeely}diuFI-"
	$string9 = "ttec]tr"
	$string10 = "fSgcso"
	$string11 = "eig.t)eR{t}aeesbdtbl{1sr)m"
	$string12 = ").}n,Raa.s"
	$string13 = "sLtfcb.nrf{Wiantscncad1ac)scb0eo]}Diuu(nar"
	$string14 = "dxc.,:tfr(ucxRn"
	$string15 = "eDnnforbyri(tbmns).[i.ee;dl(aNimp(l(h[u[ti;u)"
	$string16 = "}tn)i{ebr,_.ns(Nes,,gm(ar.t"
	$string17 = "l]it}N(pe3,iaaLds.)lqea:Ps00Hc;[{Euihlc)LiLI"
condition:
	17 of them
}
rule phoenix_html3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "d7cacbff6438d866998fc8bfee18102d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "mtfla/,)asaf)'}"
	$string1 = "72267E7C'A3035CFC415DFAAA834B208D8C230FD303E2EFFE386BE05960C588C6E85650746E690C39F706F97DC74349BA134"
	$string2 = "N'eiui7F6e617e00F145A002645E527BFF264842F877B2FFC1FE84BCC6A50F0305B5B0C36A019F53674FD4D3736C494BD5C2"
	$string3 = "lndl}})<>"
	$string4 = "otodc};b<0:D>r5d4u%c005u%0028u%251eu%a095u%6028u%0028u%2500u%f7f7u%70d7u%2025u%9008u%08f8u%c607usu%3"
	$string5 = "tuJaboaopb"
	$string6 = "a(vxf{p'tSowa.i,1NIWm("
	$string7 = "2004et"
	$string8 = "2054sttE5356496478"
	$string9 = "yi%A%%A%%A%%A%Cvld3,5314,004,6211,931,,,011394617,983,1154,5,1,,1,1,13,08,4304,1"
	$string10 = "0ovel04ervEeieeem)h))B(ihsAE;u%04b8u%1c08u%0e50u%a000u%1010u%4000u%20afu%0006u%2478u%0020u%1065u%210"
	$string11 = "/gmi,String.fromCharCode(2"
	$string12 = "ncBcaocta.ye"
	$string13 = "0201010030004A033102090;na"
	$string14 = "66u%0(ec'h{iis%%A%%A%%A%%A%frS1,,8187,1,4,11,91516,,61,,10841,1,13,,,11248,01818849,23,,,,791meits0e"
	$string15 = "D11C0002C0069733E60656F6462070D000402DFF200696E"
	$string16 = "810p0y98"
	$string17 = "9,0,e'Fm692E583760"
	$string18 = "57784234633a)(u"
condition:
	18 of them
}
rule phoenix_html4
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "61fde003211ac83c2884fbecefe1fc80"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/dr.php"
	$string1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string2 = "launchjnlp"
	$string3 = "clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA"
	$string4 = "urlmon.dll"
	$string5 = "<body>"
	$string6 = " docbase"
	$string7 = "</html>"
	$string8 = " classid"
	$string9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string10 = "63AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string11 = "</object>"
	$string12 = "application/x-java-applet"
	$string13 = "java_obj"
condition:
	13 of them
}
rule phoenix_html5
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "30afdca94d301905819e00a7458f4a4e"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "dtesu}"
	$string1 = "<textarea>function gvgsxoy(gwcqg1){return gwcqg1.replace(/"
	$string2 = "v}Ahnhxwet"
	$string3 = "0125C6BBA2B84F7A1D2940C04C8B7449A40EEB0D14C8003535C0042D75E05F0D7F3E0A7B4E33EB4D8D47119290FC"
	$string4 = "a2Fs2325223869e'Fm2873367130"
	$string5 = "m0000F0F6E66607C71646F6607000107FA61021F6060(aeWWIN"
	$string6 = ")(r>hd1/dNasmd(fpas"
	$string7 = "9,0,e'Fm692E583760"
	$string8 = "5ud(dis"
	$string9 = "nacmambuntcmi"
	$string10 = "Fa078597467,1C0e674366871,'2F"
	$string11 = "Fa56F386A76,180e828592024,'2F"
	$string12 = "alA)(2avoyOi;ic)t6])teptp,an}tnv0i'fms<uic"
	$string13 = "iR'nandee"
	$string14 = "('0.aEa-9leal"
	$string15 = "bsD0seF"
	$string16 = "t.ck263/6F3a001CE7A2684067F98BEC18B738801EF1F7F7E49A088695050C000865FC38080FE23727E0E8DE9CB53E748472"
condition:
	16 of them
}
rule phoenix_html6
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "4aabb710cf04240d26c13dd2b0ccd6cc"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "F4B6B2E67)A780A373A633;ast2316363677fa'es6F3635244"
	$string1 = "piia.a}rneecc.cnuoir"
	$string2 = "0448D5A54BE10A5DA628100AC3F3D53C9CAEBFF7E1E805080B044057CB1C0EF7F263DC64E0CBE47C2A21E55E9EA620000106"
	$string3 = "],enEn..o"
	$string4 = "o;1()sna"
	$string5 = "(eres(0.,"
	$string6 = "}fs2he}o.t"
	$string7 = "f'u>jisch3;)Ie)C'eO"
	$string8 = "refhiacei"
	$string9 = "0026632528(sCE7A2684067F98BEC1s00000F512Fm286631666"
	$string10 = "vev%80b4u%ee18u%28b8u%2617u%5c08u%0e50u%a000u%9006u%76efu%b1cbu%ba2fu%6850u%0524u%9720u%f70<}1msa950"
	$string11 = "pdu,xziien,ie"
	$string12 = "rr)l;.)vr.nbl"
	$string13 = "ii)ruccs)1e"
	$string14 = "F30476737930anD<tAhnhxwet"
	$string15 = ")yf{(ee..erneef"
	$string16 = "ieiiXuMkCSwetEet"
	$string17 = "F308477E7A7itme"
condition:
	17 of them
}
rule phoenix_html7
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "f0e1b391ec3ce515fd617648bec11681"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "EBF0a0001B05D266503046C7A491A0C00044F0002035D0D0twl''WIN"
	$string1 = "ah80672528657"
	$string2 = "n);tctt)Eltc(Dj"
	$string3 = ";cnt2<tEf"
	$string4 = "iwkne){bvfvgzg5"
	$string5 = "..'an{ea-Ect'8-huJ.)/l'/tCaaa}<Ct95l"
	$string6 = "'WIWhaFtF662F6577IseFe427347637"
	$string7 = "ddTh75e{"
	$string8 = "Ae'n,,9"
	$string9 = "%E7E3Vemtyi"
	$string10 = "cf'treran"
	$string11 = "ncBcaocta.ye"
	$string12 = ")'0,p8k"
	$string13 = "0;{tc4F}c;eptdpduoCuuedPl80evD"
	$string14 = "iq,q,Nd(nccfr'Bearc'nBtpw"
	$string15 = ";)npeits0e.uvhF$I'"
	$string16 = "nvasai0.-"
	$string17 = "lmzv'is'"
condition:
	17 of them
}
rule phoenix_html8
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "1c19a863fc4f8b13c0c7eb5e231bc3d1"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0x5)).replace(/"
	$string1 = "%A%%A%%nc(,145,9,84037,1711,,4121,56,1,,0505,,651,,3,514101,01,29,7868,90"
	$string2 = "/gmi,String.fromCharCode(2"
	$string3 = "turt;oo)s"
	$string4 = "91;var jtdpar"
	$string5 = "R(,13,7,63,48140601,5057,,319,,6,1,1,2,,110,0,1011171,2319,,,,10vEAs)tfmneyeh%A%%A%%A%%A%s<u91,4693,"
	$string6 = "y%%A%%A%%A%%A.meo21117,7,1,,10,1,9,8,1,9,100,6,141003,74181,163,441114,43,207,,remc'ut"
	$string7 = "epjtjqe){jtdpar"
	$string8 = "/gmi,'"
	$string9 = "<font></font><body id"
	$string10 = " epjtjqe; fqczi > 0; fqczi--){for (bwjmgl7 "
	$string11 = "nbte)bb(egs%A%%A%%A%%A%%m"
	$string12 = "fvC9614165,,,1,1801151030,,0,,487641114,,1,141,914810036,,888,201te.)'etdc:ysaA%%A%%A%%A%%5sao,61,0,"
	$string13 = "(tiAmrd{/tnA%%A%%A%%A%%Aiin11,,1637,34191,626958314,11007,,61145,411,7,9,1821,,43,8311,26;d'ebt.dyvs"
	$string14 = "A%%A%%A%%Ao"
	$string15 = "hrksywd(cpkwisk4);/"
	$string16 = ";</script>"
condition:
	16 of them
}
rule phoenix_html9
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "742d012b9df0c27ed6ccf3b234db20db"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "tute)bbr:"
	$string1 = "nfho(tghRx"
	$string2 = "()irfE/Rt..cOcC"
	$string3 = "NcEnevbf"
	$string4 = "63FB8B4296BBC290A0.'0000079'Fh20216B6A6arA;<"
	$string5 = "wHe(cLnyeyet(a.i,r.{.."
	$string6 = "tute)bbdfiiix'bcr"
	$string7 = "itifdf)d1L2f'asau%d004u%8e00u%0419u%a58du%2093u%ec10u%0050u%00d4u%4622u%bcd1u%b1ceu%5000u%f7f5u%5606"
	$string8 = "2F4693529783'82F076676C38'te"
	$string9 = "sm(teoeoi)cfh))pihnipeeeo}.,(.(("
	$string10 = "ao)ntavlll{))ynlcoix}hiN.il'tes1ad)bm;"
	$string11 = "i)}m0f(eClei(/te"
	$string12 = "}aetsc"
	$string13 = "irefnig.pT"
	$string14 = "a0mrIif/tbne,(wsk,"
	$string15 = "500F14B06000000630E6B72636F60632C6E711C6E762E646F147F44767F650A0804061901020009006B120005A2006L"
	$string16 = ".hB.Csf)ddeSs"
	$string17 = "tnne,IPd4Le"
	$string18 = "hMdarc'nBtpw"
condition:
	18 of them
}
rule phoenix_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "a8a18219b02d30f44799415ff19c518e"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "qX$8$a"
	$string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
	$string3 = "a.classPK"
	$string4 = "6;\\Q]Q"
	$string5 = "h[s] X"
	$string6 = "ToolsDemoSubClass.classPK"
	$string7 = "a.class"
	$string8 = "META-INF/MANIFEST.MFPK"
	$string9 = "ToolsDemoSubClass.classeO"
	$string10 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProviderPK"
condition:
	10 of them
}
rule phoenix_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "989c5b5eaddf48010e62343d7a4db6f4"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "a66d578f084.classeQ"
	$string1 = "a4cb9b1a8a5.class"
	$string2 = ")szNu\\MutK"
	$string3 = "qCCwBU"
	$string4 = "META-INF/MANIFEST.MF"
	$string5 = "QR,GOX"
	$string6 = "ab5601d4848.classmT"
	$string7 = "a6a7a760c0e["
	$string8 = "2ZUK[L"
	$string9 = "2VT(Au5"
	$string10 = "a6a7a760c0ePK"
	$string11 = "aa79d1019d8.class"
	$string12 = "aa79d1019d8.classPK"
	$string13 = "META-INF/MANIFEST.MFPK"
	$string14 = "ab5601d4848.classPK"
condition:
	14 of them
}
rule phoenix_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "c5655c496949f8071e41ea9ac011cab2"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "'> >$>"
	$string1 = "bpac/PK"
	$string2 = "bpac/purok$1.classmP]K"
	$string3 = "bpac/KAVS.classmQ"
	$string4 = "'n n$n"
	$string5 = "bpac/purok$1.classPK"
	$string6 = "$.4aX,Gt<"
	$string7 = "bpac/KAVS.classPK"
	$string8 = "bpac/b.classPK"
	$string9 = "bpac/b.class"
condition:
	9 of them
}
rule phoenix_pdf
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "16de68e66cab08d642a669bf377368da"
	hash1 = "bab281fe0cf3a16a396550b15d9167d5"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0000000254 00000 n"
	$string1 = "0000000295 00000 n"
	$string2 = "trailer<</Root 1 0 R /Size 7>>"
	$string3 = "0000000000 65535 f"
	$string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string5 = "0000000120 00000 n"
	$string6 = "%PDF-1.0"
	$string7 = "startxref"
	$string8 = "0000000068 00000 n"
	$string9 = "endobjxref"
	$string10 = ")6 0 R ]>>endobj"
	$string11 = "0000000010 00000 n"
condition:
	11 of them
}
rule phoenix_pdf2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "33cb6c67f58609aa853e80f718ab106a"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "\\nQb<%"
	$string1 = "0000000254 00000 n"
	$string2 = ":S3>v0$EF"
	$string3 = "trailer<</Root 1 0 R /Size 7>>"
	$string4 = "%PDF-1.0"
	$string5 = "0000000000 65535 f"
	$string6 = "endstream"
	$string7 = "0000000010 00000 n"
	$string8 = "6 0 obj<</JS 7 0 R/S/JavaScript>>endobj"
	$string9 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string10 = "}pr2IE"
	$string11 = "0000000157 00000 n"
	$string12 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
	$string13 = "5 0 obj<</Names[("
condition:
	13 of them
}
rule phoenix_pdf3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "bab281fe0cf3a16a396550b15d9167d5"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "trailer<</Root 1 0 R /Size 7>>"
	$string1 = "stream"
	$string2 = ";_oI5z"
	$string3 = "0000000010 00000 n"
	$string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string5 = "7 0 obj<</Filter[ /FlateDecode /ASCIIHexDecode /ASCII85Decode ]/Length 3324>>"
	$string6 = "endobjxref"
	$string7 = "L%}gE("
	$string8 = "0000000157 00000 n"
	$string9 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
	$string10 = "0000000120 00000 n"
	$string11 = "4 0 obj<</Type/Page/Parent 2 0 R /Contents 12 0 R>>endobj"
condition:
	11 of them
}
rule Pikahook
{
    meta:
        author = "kevoreilly"
        description = "Pikabot anti-hook bypass"
        cape_options = "clear,sysbp=$indirect+40,sysbpmode=1,force-sleepskip=1"
        packed = "89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9"
    strings:
        $indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1 [4] FF 15}
        $sysenter1 = {89 44 24 08 8D 85 20 FC FF FF C7 44 24 04 FF FF 1F 00 89 04 24 E8}
        $sysenter2 = {C7 44 24 0C 00 00 00 02 C7 44 24 08 00 00 00 02 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PikExport
{
    meta:
        author = "kevoreilly"
        description = "Pikabot export selection"
        cape_options = "export=$export"
        hash = "238dcc5611ed9066b63d2d0109c9b623f54f8d7b61d5f9de59694cfc60a4e646"
    strings:
        $export = {55 8B EC 83 EC ?? C6 45 [2] C6 45 [2] C6 45 [2] C6 45 [2] C6 45}
        $pe = {B8 08 00 00 00 6B C8 00 8B 55 ?? 8B 45 ?? 03 44 0A 78 89 45 ?? 8B 4D ?? 8B 51 18 89 55 E8 C7 45 F8 00 00 00 00}
    condition:
        uint16(0) == 0x5A4D and all of them
}
// Operation Potao yara rules
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
import "pe"

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
}// Operation Groundbait yara rules
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
rule Prometei_Main
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
rule PureZip
{
    meta:
        id = "3irhYCOx5n1gPEoxWCpDiE"
        fingerprint = "c713faeaeb58701fd04353ef6fd17e4677da735318c43658d62242cd2ca3718d"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ZIP files with a hidden file named '__.exe', as seen in a massive PureCrypt campaign in Q1 2024."
        category = "MALWARE"
        malware = "Pure"
        malware_family= "INFOSTEALER"
        hash = "ff668ef41336749df82e897c36b1438da1a21b1816716b30183024a8b62342a2"

strings:
    //This pattern is always the same. ZIP is sometimes password-protected. But typically 2 files, where __.exe is a hidden file.
    //These are all PureCrypt samples, but may drop anything from PureLogs to Agent Tesla to RedLine to...
    $exe = {5F 5F 2E 65 78 65} //__.exe

condition:
    uint16(0) == 0x4b50 and $exe in (filesize-300..filesize)
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
        last_modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable converted using PyInstaller. This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"

    strings:
        $ = "pyi-windows-manifest-filename" ascii wide
        $ = "pyi-runtime-tmpdir" ascii wide
        $ = "PyInstaller: " ascii wide

    condition:
        uint16(0)==0x5a4d and any of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="20d36c0a435caad0ae75d3e5f474650c"))
}
rule Pysa
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
}rule QakBot5
{
    meta:
        author = "kevoreilly"
        description = "QakBot v5 Payload"
        cape_type = "QakBot Payload"
        packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"
    strings:
        $loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
        $conf = {0F B7 1D [4] B9 [2] 00 00 E8 [4] 8B D3 48 89 45 ?? 45 33 C9 48 8D 0D [4] 4C 8B C0 48 8B F8 E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule QakBot4
{
    meta:
        author = "kevoreilly"
        description = "QakBot v4 Payload"
        cape_type = "QakBot Payload"
    strings:
        $crypto1 = {8B 5D 08 0F B6 C2 8A 16 0F B6 1C 18 88 55 13 0F B6 D2 03 CB 03 CA 81 E1 FF 00 00 80 79 08 49 81 C9 00 FF FF FF 41}
        $sha1_1 = {5? 33 F? [0-9] 89 7? 24 ?? 89 7? 24 ?? 8? [1-3] 24 [1-4] C7 44 24 ?0 01 23 45 67 C7 44 24 ?4 89 AB CD EF C7 44 24 ?8 FE DC BA 98 C7 44 24 ?C 76 54 32 10 C7 44 24 ?0 F0 E1 D2 C3}
        $sha1_2 = {33 C0 C7 01 01 23 45 67 89 41 14 89 41 18 89 41 5C C7 41 04 89 AB CD EF C7 41 08 FE DC BA 98 C7 41 0C 76 54 32 10 C7 41 10 F0 E1 D2 C3 89 41 60 89 41 64 C3}
        $anti_sandbox1 = {8D 4? FC [0-1] E8 [4-7] E8 [4] 85 C0 7E (04|07) [4-7] 33 (C0|D2) 74 02 EB FA}
        $anti_sandbox2 = {8D 45 ?? 50 E8 [2] 00 00 59 68 [4] FF 15 [4] 89 45 ?? 83 7D ?? 0F 76 0C}
        $decrypt_config1 = {FF 37 83 C3 EC 53 8B 5D 0C 8D 43 14 50 6A 14 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 ?? 26 ?? ?? 86 20 02 00 00 66 85 C0 ?? ?? FF 37 FF 75 10 53}
        $decrypt_config2 = {8B 45 08 8B 88 24 04 00 00 51 8B 55 10 83 EA 14 52 8B 45 0C 83 C0 14 50 6A 14 8B 4D 0C 51 E8 6C 08 00 00}
        $decrypt_config3 = {6A 13 8B CE 8B C3 5A 8A 18 3A 19 75 05 40 41 4A 75 F5 0F B6 00 0F B6 09 2B C1 74 05 83 C8 FF EB 0E}
        $call_decrypt = {83 7D ?? 00 56 74 0B FF 75 10 8B F3 E8 [4] 59 8B 45 0C 83 F8 28 72 19 8B 55 08 8B 37 8D 48 EC 6A 14 8D 42 14 52 E8}
    condition:
        uint16(0) == 0x5A4D and any of ($*)
}
rule RagnarLocker
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
}// Linux/Rakos yara rule
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
rule Ramnit
{
    meta:
        author = "kevoreilly"
        description = "Ramnit Payload"
        cape_type = "Ramnit Payload"
    strings:
        $DGA = {33 D2 B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 F7 E2 8B D1 8B C8 B8 14 0B 00 00 F7 E2 2B C8 33 D2 8B C1 8B}
        $xor_loop = {83 7D 0C 00 74 27 83 7D 14 00 74 21 8B 4D 0C 8B 7D 08 8B 75 10 BA 00 00 00 00 0B D2 75 04 8B 55 14 4A 8A 1C 32 32 1F 88 1F 47 4A E2 ED}
        $id_string = "{%08X-%04X-%04X-%04X-%08X%04X}"
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
import "hash"
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
        category = "INFO"
        reference = "https://rclone.org/"


    strings:
        $ = "github.com/rclone/" ascii wide
        $ = "The Rclone Authors" ascii wide
        $ = "It copies the drive file with ID given to the path" ascii wide
        $ = "rc vfs/forget file=hello file2=goodbye dir=home/junk" ascii wide
        $ = "rc to flush the whole directory cache" ascii wide

    condition:
        any of them or for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="fc675e36c61c8b9d0b956bd05695cdda")
}
rule RCSession
{
    meta:
        author = "kevoreilly"
        description = "RCSession Payload"
        cape_type = "RCSession Payload"
    strings:
        $a1 = {56 33 F6 39 74 24 08 7E 4C 53 57 8B F8 2B FA 8B C6 25 03 00 00 80 79 05 48 83 C8 FC 40 83 E8 00 74 19 48 74 0F 48 74 05 6B C9 09 EB 15 8B C1 C1 E8 02 EB 03 8D 04 09 2B C8}
        $a2 = {83 C4 10 85 C0 74 ?? BE ?? ?? ?? ?? 89 74 24 10 E8 ?? ?? ?? ?? 6A 03 68 48 0B 00 00 56 53 57 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 18 85 C0 74 18 E8 ?? ?? ?? ?? 6A 03 68 48}
    condition:
        (any of ($a*))
}
rule RDPWrap
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
rule RdtscpAntiVM
{
    meta:
        author = "kevoreilly"
        description = "RdtscpAntiVM bypass"
        cape_options = "nop-rdtscp=1"
    strings:
        $antivm = {46 0F 01 F9 [0-4] 66 0F 6E C6 F3 0F E6 C0 66 0F 2F ?? 73}
    condition:
        any of them
}
rule redkit_bin_basic : exploit_kit
{
    strings:
        $a = /\/\d{2}.html\s/
    condition:
        $a
}rule RedLine_a
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
}rule Remcos
{
    meta:
        author = "kevoreilly"
        description = "Remcos Payload"
        cape_type = "Remcos Payload"
    strings:
        $name  = "Remcos" nocase
        $time   = "%02i:%02i:%02i:%03i"
        $crypto1 = {81 E1 FF 00 00 80 79 ?? 4? 81 C9 00 FF FF FF 4? 8A ?4 8?}
        $crypto2 = {0F B6 [1-7] 8B 45 08 [0-2] 8D 34 07 8B 01 03 C2 8B CB 99 F7 F9 8A 84 95 ?? ?? FF FF 30 06 47 3B 7D 0C 72}
    condition:
        uint16(0) == 0x5A4D and ($name) and ($time) and any of ($crypto*)
}
rule Responder
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
}import "pe"

rule REvil_Cert
{
    meta:
        id = "4KM2J6a6EP4OW0GGQEaBiI"
        fingerprint = "ab9783909f458776d59b75d74f885dfebcc543b690c5e46b738a28f25d651a9c"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
        category = "MALWARE"
        malware = "REVIL"
        malware_type = "RANSOMWARE"
        mitre_att = "S0496"
        reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"


    condition:
        uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0")
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
}rule Rhadamanthys
{
    meta:
        author = "kevoreilly"
        cape_options = "bp0=$conf-11,hc0=1,action0=setdump:edx::ebx,bp1=$conf+64,hc1=1,action1=dump,count=0,typestring=Rhadamanthys Config,ntdll-protect=0"
        packed = "9e28586ab70b1abdccfe087d81e326a0703f75e9551ced187d37c51130ad02f5"
    strings:
        $rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
        $code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
        $conf = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
    condition:
        2 of them
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
rule RisePro
{
    meta:
        author = "kevoreilly"
        //cape_options = "br0=$decode1-49,action1=string:eax,count=1,bp2=$decode2+25,action2=string:eax"
        cape_options = "bp0=$c2+15,action0=string:edx,bp1=$c2+41,action1=string:ecx,count=1"
        hash = "1b69a1dd5961241b926605f0a015fa17149c3b2759fb077a30a22d4ddcc273f6"
    strings:
        $decode1 = {8A 06 46 84 C0 75 F9 2B F1 B8 FF FF FF 7F 8B 4D ?? 8B 51 ?? 2B C2 3B C6 72 38 83 79 ?? 10 72 02 8B 09 52 51 56 53 51 FF 75 ?? 8B CF E8}
        $decode2 = {8B D9 81 FF FF FF FF 7F 0F [2] 00 00 00 C7 43 ?? 0F 00 00 00 83 FF 10 73 1A 57 FF 75 ?? 89 7B ?? 53 E8 [4] 83 C4 0C C6 04 1F 00 5F 5B 5D C2 08 00}
        $c2 = {FF 75 30 83 3D [4] 10 BA [4] B9 [4] 0F 43 15 [4] 83 3D [4] 10 0F 43 0D [4] E8 [4] A3}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule RokRat
{
    meta:
        author = "kevoreilly"
        description = "RokRat Payload"
        cape_type = "RokRat Payload"
    strings:
        $code1 = {8B 57 04 8D 7F 04 33 57 FC 81 E2 FF FF FF 7F 33 57 FC 8B C2 24 01 0F B6 C0 F7 D8 1B C0 D1 EA 25 DF B0 08 99 33 87 30 06 00 00 33 C2 89 87 3C F6 FF FF 83 E9 01 75 C9}
        $string1 = "/pho_%s_%d.jpg" wide
    condition:
        uint16(0) == 0x5A4D and (any of ($code*)) and (any of ($string*))
}
rule RoyalRoad_RTF
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
}rule Rozena
{
    meta:
        cape_type = "Rozena Payload"
    strings:
        $ip_port = {FF D5 6A 0A 68 [4] 68 [4] 89 E6 50 50 50 50 40 50 40 50 68 [4] FF D5}
        $socket = {6A 00 6A 04 56 57 68 [4] FF D5 [0-5] 8B 36 6A 40 68 00 10 00 00 56 6A 00 68}
    condition:
        all of them
}
rule Ryuk
{
    meta:
        author = "kevoreilly"
        description = "Ryuk Payload"
        cape_type = "Ryuk Payload"
    strings:
        $ext = ".RYK" wide
        $readme = "RyukReadMe.txt" wide
        $main = "InvokeMainViaCRT"
        $code = {48 8B 4D 10 48 8B 03 48 C1 E8 07 C1 E0 04 F7 D0 33 41 08 83 E0 10 31 41 08 48 8B 4D 10 48 8B 03 48 C1 E8 09 C1 E0 03 F7 D0 33 41 08 83 E0 08 31 41 08}
    condition:
        uint16(0) == 0x5A4D and 3 of ($*)
}
rule SaintBot
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
rule sakura_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Sakura Exploit Kit Detection"
	hash0 = "a566ba2e3f260c90e01366e8b0d724eb"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Rotok.classPK"
	$string1 = "nnnolg"
	$string2 = "X$Z'\\4^=aEbIdUmiprsxt}v<" wide
	$string3 = "()Ljava/util/Set;"
	$string4 = "(Ljava/lang/String;)V"
	$string5 = "Ljava/lang/Exception;"
	$string6 = "oooy32"
	$string7 = "Too.java"
	$string8 = "bbfwkd"
	$string9 = "Ljava/lang/Process;"
	$string10 = "getParameter"
	$string11 = "length"
	$string12 = "Simio.java"
	$string13 = "Ljavax/swing/JList;"
	$string14 = "-(Ljava/lang/String;)Ljava/lang/StringBuilder;"
	$string15 = "Ljava/io/InputStream;"
	$string16 = "vfnnnrof.exnnnroe"
	$string17 = "Olsnnfw"
condition:
	17 of them
}
rule sakura_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Sakura Exploit Kit Detection"
	hash0 = "d21b4e2056e5ef9f9432302f445bcbe1"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "getProperty"
	$string1 = "java/io/FileNotFoundException"
	$string2 = "LLolp;"
	$string3 = "cjhgreshhnuf "
	$string4 = "StackMapTable"
	$string5 = "onfwwa"
	$string6 = "(C)Ljava/lang/StringBuilder;"
	$string7 = "replace"
	$string8 = "LEsia$fffgss;"
	$string9 = "<clinit>"
	$string10 = "()Ljava/io/InputStream;"
	$string11 = "openConnection"
	$string12 = " gjhgreshhnijhgreshhrtSjhgreshhot.sjhgreshhihjhgreshht;)"
	$string13 = "Oi.class"
	$string14 = " rjhgreshhorjhgreshhre rajhgreshhv"
	$string15 = "java/lang/String"
	$string16 = "java/net/URL"
	$string17 = "Created-By: 1.7.0-b147 (Oracle Corporation)"
condition:
	17 of them
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
}rule Scarab
{
    meta:
        author = "kevoreilly"
        description = "Scarab Payload"
        cape_type = "Scarab Payload"
    strings:
        $crypt1 = {8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08 33 D8 8B C3 42 8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08 33 D8 8B C3 42 8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08}
        $crypt2 = {8B 4C 82 0C 8B D9 C1 E3 18 C1 E9 08 0B D9 8B CB 0F B6 D9 8B 1C 9D AC 0C 43 00 89 5C 24 04 8B D9 C1 EB 08 0F B6 DB 8B 34 9D AC 0C 43 00 8B D9 C1 EB 10}
        $crypt3 = {8B 13 8B CA 81 E1 80 80 80 80 8B C1 C1 E8 07 50 8B C1 59 2B C1 25 1B 1B 1B 1B 8B CA 81 E1 7F 7F 7F 7F 03 C9 33 C1 8B C8 81 E1 80 80 80 80 8B F1 C1 EE 07}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Sedreco
{
    meta:
        author = "kevoreilly"
        description = "Sedreco encrypt function entry"
        cape_type = "Sedreco Payload"
    strings:
        $encrypt1 = {55 8B EC 83 EC 2C 53 56 8B F2 57 8B 7D 08 B8 AB AA AA AA}
        $encrypt2 = {55 8B EC 83 EC 20 8B 4D 10 B8 AB AA AA AA}

        $encrypt64_1 = {48 89 4C 24 08 53 55 56 57 41 54 41 56 48 83 EC 18 45 8D 34 10 48 8B E9 B8 AB AA AA AA 4D 8B E1 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA}

    condition:
        uint16(0) == 0x5A4D and $encrypt1 or $encrypt2 or $encrypt64_1
}
rule Seduploader
{
    meta:
        author = "kevoreilly"
        description = "Seduploader decrypt function"
        cape_type = "Seduploader Payload"
    strings:
        $decrypt1 = {8D 0C 30 C7 45 FC 0A 00 00 00 33 D2 F7 75 FC 8A 82 ?? ?? ?? ?? 32 04 0F 88 01 8B 45 0C 40 89 45 0C 3B C3 7C DB}
    condition:
        uint16(0) == 0x5A4D and any of ($decrypt*)
}
rule Sfile
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
rule SingleStepAntiHook
{
    meta:
        author = "kevoreilly"
        description = "Single-step anti-hook Bypass"
        cape_options = "bp0=$antihook+6,action0=skip,count=0"
    strings:
        $antihook = {FF D? 83 EC 08 9C 81 0C 24 00 01 00 00 9D}
    condition:
        any of them
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
rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        cape_options = "bp0=$gate+19,action0=DumpSectionViews,count=1"
    strings:
        $gate = {68 [2] 00 00 50 E8 [4] 8B 45 ?? 89 F1 8B 55 ?? 9A [2] 40 00 33 00 89 F9 89 FA 81 C1 [2] 00 00 81 C2 [2] 00 00 89 0A 8B 46 ?? 03 45 ?? 8B 4D ?? 8B 55 ?? 9A [2] 40 00 33 00}
    condition:
        uint16(0) == 0x5A4D and any of them
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
        category = "INFO"
        reference = "https://twitter.com/malwrhunterteam/status/1483132689586831365"

    strings:
        $ = "SPecialiST RePack" ascii wide
        $ = {53 50 65 63 69 61 6C 69 53 54 20 52 65 50 61 63 6B}

    condition:
        any of them
}
rule SquirrelWaffle
{
    meta:
        author = "kevoreilly & R3MRUM"
        cape_type = "SquirrelWaffle Payload"
    strings:
        $code = {8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39 8D 4D ?? 0F B6 C0 50 6A 01 E8 [4] C6 45}
        $decode = {F7 75 ?? 83 7D ?? 10 8D 4D ?? 8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39}
    condition:
        uint16(0) == 0x5A4D and all of them
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
rule StealcAnti
{
    meta:
        author = "kevoreilly"
        description = "Stealc detonation bypass"
        cape_options = "bp0=$anti+17,action0=skip,count=1"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $anti = {53 57 57 57 FF 15 [4] 8B F0 74 03 75 01 B8 E8 [4] 74 03 75 01 B8}
        $decode = {6A 03 33 D2 8B F8 59 F7 F1 8B C7 85 D2 74 04 2B C2 03 C1 6A 06 C1 E0 03 33 D2 59 F7 F1}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule StealcStrings
{
    meta:
        author = "kevoreilly"
        description = "Stealc string decryption"
        cape_options = "bp0=$decode+17,action0=string:edx,count=1,typestring=Stealc Strings"
        packed = "d0c824e886f14b8c411940a07dc133012b9eed74901b156233ac4cac23378add"
    strings:
        $decode = {51 8B 15 [4] 52 8B 45 ?? 50 E8 [4] 83 C4 0C 6A 04 6A 00 8D 4D ?? 51 FF 15 [4] 83 C4 0C 8B 45 ?? 8B E5 5D C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule Syscall
{
    meta:
        author = "kevoreilly"
        description = "x64 syscall instruction (direct)"
        cape_options = "clear,dump,sysbp=$syscall0+8,sysbp=$syscallA+10,sysbp=$syscallB+7,sysbp=$syscallC+18"
    strings:
        $syscall0 = {4C 8B D1 B8 [2] 00 00 (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov eax, X
        $syscallA = {4C 8B D1 66 8B 05 [4] (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov ax, [p]
        $syscallB = {4C 8B D1 66 B8 [2] (0F 05|FF 25 ?? ?? ?? ??) C3}       // mov ax, X
        $syscallC = {4C 8B D1 B8 [2] 00 00 [10] 0F 05 C3}
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
}// For feedback or questions contact us at: github@eset.com
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
rule TClient
{
    meta:
        author = "kevoreilly"
        description = "TClient Payload"
        cape_type = "TClient Payload"
    strings:
        $code1 = {41 0F B6 00 4D 8D 40 01 34 01 8B D7 83 E2 07 0F BE C8 FF C7 41 0F BE 04 91 0F AF C1 41 88 40 FF 81 FF 80 03 00 00 7C D8}
    condition:
        uint16(0) == 0x5A4D and any of ($code*)
}
rule TrickBot
{
    meta:
        author = "sysopfb & kevoreilly"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
        $str2 = "group_tag" ascii wide
        $str3 = "client_id" ascii wide
        $code1 = {8A 11 88 54 35 F8 46 41 4F 89 4D F0 83 FE 04 0F 85 7E 00 00 00 8A 1D ?? ?? ?? ?? 33 F6 8D 49 00 33 C9 84 DB 74 1F 8A 54 35 F8 8A C3 8D 64 24 00}
        $code2 = {8B 4D FC 8A D1 02 D2 8A C5 C0 F8 04 02 D2 24 03 02 C2 88 45 08 8A 45 FE 8A D0 C0 FA 02 8A CD C0 E1 04 80 E2 0F 32 D1 8B 4D F8 C0 E0 06 02 45 FF 88 55 09 66 8B 55 08 66 89 11 88 41 02}
        $code3 = {0F B6 54 24 49 0F B6 44 24 48 48 83 C6 03 C0 E0 02 0F B6 CA C0 E2 04 C0 F9 04 33 DB 80 E1 03 02 C8 88 4C 24 40 0F B6 4C 24 4A 0F B6 C1 C0 E1 06 02 4C 24 4B C0 F8 02 88 4C 24 42 24 0F}
        $code4 = {53 8B 5C 24 18 55 8B 6C 24 10 56 8B 74 24 18 8D 9B 00 00 00 00 8B C1 33 D2 F7 F3 41 8A 04 2A 30 44 31 FF 3B CF 75 EE 5E 5D 5B 5F C3}
        $code5 = {50 0F 31 C7 44 24 04 01 00 00 00 8D 0C C5 00 00 00 00 F7 C1 F8 07 00 00 74 1B 48 C1 E2 20 48 8B C8 48 0B CA 0F B6 C9 C1 E1 03 F7 D9 C1 64 24 04 10 FF C1 75 F7 59 C3}
        $code6 = {53 8B 5C 24 0C 56 8B 74 24 14 B8 ?? ?? ?? ?? F7 E9 C1 FA 02 8B C2 C1 E8 1F 03 C2 6B C0 16 8B D1 2B D0 8A 04 1A 30 04 31 41 3B CF 75 DD 5E 5B 5F C3}
        $code7 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        all of ($str*) or any of ($code*)
}

rule Trickbot_PermaDll_UEFI_Module
{
    meta:
        author = "@VK_Intel | Advanced Intelligence"
        description = "Detects TrickBot Banking module permaDll"
        md5 = "491115422a6b94dc952982e6914adc39"
    strings:
        $module_cfg = "moduleconfig"
        $str_imp_01 = "Start"
        $str_imp_02 = "Control"
        $str_imp_03 = "FreeBuffer"
        $str_imp_04 = "Release"
        $module = "user_platform_check.dll"
        $intro_routine = { 83 ec 40 8b ?? ?? ?? 53 8b ?? ?? ?? 55 33 ed a3 ?? ?? ?? ?? 8b ?? ?? ?? 56 57 89 ?? ?? ?? a3 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 75 ?? 8d ?? ?? ?? 89 ?? ?? ?? 50 6a 40 8d ?? ?? ?? ?? ?? 55 e8 ?? ?? ?? ?? 85 c0 78 ?? 8b ?? ?? ?? 85 ff 74 ?? 47 57 e8 ?? ?? ?? ?? 8b f0 59 85 f6 74 ?? 57 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c eb ??}
    condition:
        6 of them
}
rule TSCookie
{
    meta:
        author = "kevoreilly"
        description = "TSCookie Payload"
        cape_type = "TSCookie Payload"
    strings:
        $string1 = "http://%s:%d" wide
        $string2 = "/Default.aspx" wide
        $string3 = "\\wship6"
    condition:
        uint16(0) == 0x5A4D and all of them
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

import "pe"

private rule not_ms {
    condition:
        not for any i in (0..pe.number_of_signatures - 1):
        (
            pe.signatures[i].issuer contains "Microsoft Corporation"
        )
}

rule turla_outlook_gen {
    meta:
        author      = "ESET Research"
        date        = "05-09-2018"
        description = "Turla Outlook malware"
        version     = 2
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"    
    strings:
        $s1 = "Outlook Express" ascii wide
        $s2 = "Outlook watchdog" ascii wide
        $s3 = "Software\\RIT\\The Bat!" ascii wide
        $s4 = "Mail Event Window" ascii wide
        $s5 = "Software\\Mozilla\\Mozilla Thunderbird\\Profiles" ascii wide
        $s6 = "%%PDF-1.4\n%%%c%c\n" ascii wide
        $s7 = "%Y-%m-%dT%H:%M:%S+0000" ascii wide
        $s8 = "rctrl_renwnd32" ascii wide
        $s9 = "NetUIHWND" ascii wide
        $s10 = "homePostalAddress" ascii wide
        $s11 = "/EXPORT;OVERRIDE;START=-%d;END=-%d;FOLDER=%s;OUT=" ascii wide
        $s12 = "Re:|FWD:|AW:|FYI:|NT|QUE:" ascii wide
        $s13 = "IPM.Note" ascii wide
        $s14 = "MAPILogonEx" ascii wide
        $s15 = "pipe\\The Bat! %d CmdLine" ascii wide
        $s16 = "PowerShellRunner.dll" ascii wide
        $s17 = "cmd container" ascii wide
        $s18 = "mapid.tlb" ascii wide nocase
        $s19 = "Content-Type: F)*+" ascii wide fullword
    condition:
        not_ms and 5 of them
}

rule turla_outlook_filenames {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Turla Outlook filenames"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"   
    strings:
        $s1 = "mapid.tlb"
        $s2 = "msmime.dll"
        $s3 = "scawrdot.db"
    condition:
        any of them
}

rule turla_outlook_log {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "First bytes of the encrypted Turla Outlook logs"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"   
    strings:
        //Log begin: [...] TVer
        $s1 = {01 87 C9 75 C8 69 98 AC E0 C9 7B [21] EB BB 60 BB 5A}
    condition:
        $s1 at 0
}

rule turla_outlook_exports {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Export names of Turla Outlook Malware"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"  
    condition:
        (pe.exports("install") or pe.exports("Install")) and
        pe.exports("TBP_Initialize") and
        pe.exports("TBP_Finalize") and
        pe.exports("TBP_GetName") and
        pe.exports("DllRegisterServer") and
        pe.exports("DllGetClassObject")
}

rule turla_outlook_pdf {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Detect PDF documents generated by Turla Outlook malware"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"  
    strings:
        $s1 = "Adobe PDF Library 9.0" ascii wide nocase
        $s2 = "Acrobat PDFMaker 9.0"  ascii wide nocase
        $s3 = {FF D8 FF E0 00 10 4A 46 49 46}
        $s4 = {00 3F 00 FD FC A2 8A 28 03 FF D9}
        $s5 = "W5M0MpCehiHzreSzNTczkc9d" ascii wide nocase
        $s6 = "PDF-1.4" ascii wide nocase
    condition:
        5 of them
}

rule outlook_misty1 {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Detects the Turla MISTY1 implementation"             
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"  
    strings:
        //and     edi, 1FFh
        $o1 = {81 E7 FF 01 00 00}
        //shl     ecx, 9
        $s1 = {C1 E1 09}
        //xor     ax, si
        $s2 = {66 33 C6}
        //shr     eax, 7
        $s3 = {C1 E8 07}
        $o2 = {8B 11 8D 04 1F 50 03 D3 8D 4D C4}
    condition:
        $o2 and for all i in (1..#o1):
            (for all of ($s*) : ($ in (@o1[i] -500 ..@o1[i] + 500)))
}
rule Unk_BR_Banker
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
}rule Unk_Crime_Downloader_2
{
    meta:
        id = "uuvhiMCrxhHFwTkSF2Tqv"
        fingerprint = "9e6a26d06965366eaa5c3ad98fb2b120187cfb04a935e6a82effc58b23a235f0"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies what appears to be related to PureLogs stealer, but it's likely a 2nd stage with the final stage to be downloaded."
        category = "MALWARE"
        malware = "PURELOGS"
        malware_type = "DOWNLOADER"
        hash = "443b3b9929156d71ed73e99850a671a89d4d0d38cc8acc7f286696dd4f24895e"

strings:
    $unc = "UNCNOWN" ascii wide fullword
    $anti_vm1 = "WINEHDISK" ascii wide fullword
    $anti_vm2 = "(VMware|Virtual|WINE)" ascii wide
    $click_1 = "TOffersPanel" ascii wide
    $click_2 = "TOfferLabel" ascii wide
    $click_3 = "TOfferCkb" ascii wide
    $campaign = "InstallComaignsThread" ascii wide
    $net_call = "/new/net_api" ascii wide

condition:
    4 of them
}
rule Unk_DesktopLoader
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
}rule UPX
{
    meta:
        author = "kevoreilly"
        description = "UPX dump on OEP (original entry point)"
        cape_options = "bp0=$upx32+9,bp0=$upx64+11,action0=step2oep"
    strings:
        $upx32 = {6A 00 39 C4 75 FA 83 EC ?? E9}
        $upx64 = {6A 00 48 39 C4 75 F9 48 83 EC ?? E9}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule Ursnif
{
    meta:
        author = "kevoreilly & enzo"
        description = "Ursnif Payload"
        cape_type = "Ursnif Payload"
    strings:
        $crypto64_1 = {41 8B 02 ?? C1 [0-1] 41 33 C3 45 8B 1A 41 33 C0 D3 C8 41 89 02 49 83 C2 04 83 C2 FF 75 D?}
        $crypto64_2 = {44 01 44 24 10 FF C1 41 8B C0 D1 64 24 10 33 C3 41 8B D8 FF 4C 24 10 41 33 C3 01 44 24 10 D3 C8 01 44 24 10 41 89 02 49 83 C2 04 83 C2 FF 75 C3}
        $crypto64_3 = {33 C6 ?? C7 [0-1] 49 83 C2 04 33 C3 8B F1 8B CF D3 C8 89 02 48 83 C2 04 41 83 C3 FF 75 ?? 45 85 C9 75 ?? 41 83 E0 03}
        $crypto64_4 = {41 8B 02 41 8B CB 41 83 F3 01 33 C3 41 8B 1A C1 E1 03 41 33 C0 D3 C8 41 89 02 49 83 C2 04 83 C2 FF 75 C6}
        $decrypt_config64 = {44 8B D9 33 C0 45 33 C9 44 33 1D ?? ?? ?? 00 ?? ?? D2 ?? ?? D2 74 ?? 4C 8D 42 10 45 3B 0A 73 2? 45 39 58 F8 75 1C 41 F6 40 FC 01 74 12}

        $crypto32_1 = {01 45 FC D1 65 FC FF 4D FC 33 C1 33 45 0C 01 45 FC 43 8A CB D3 C8 8B CE 01 45 FC 89 02 83 C2 04 FF 4D 08 75 CD}
        $crypto32_2 = {33 C1 33 44 24 10 43 8A CB D3 C8 8B CE 89 02 83 C2 04 FF 4C 24 0C 75 D9}
        $decrypt_config32 = {8B ?? 08 5? 33 F? 3B [1-2] 74 14 A1 0? ?? ?? ?? 35 ?? ?? ?? ?? 50 8B D? E8 ?? D? 00 00 EB 02 33 C0 ?B ?? ?? ?? ?? ?? ?? ?? 74 14 8D 4D ?? ?? ?? 50 FF D? 85 C0 74 08}
    condition:
        uint16(0) == 0x5A4D and ($decrypt_config64 and any of ($crypto64*)) or ($decrypt_config32 and any of ($crypto32*))
}
rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Config Extraction"
        cape_options = "br0=$crypto32_1-48,action1=dump:ebx::eax,bp2=$crypto32_3+50,action2=dump:ebx::eax,bp3=$crypto32_4+11,action3=dump:eax::ecx,typestring=UrsnifV3 Config,count=1"
        packed = "75827be0c600f93d0d23d4b8239f56eb8c7dc4ab6064ad0b79e6695157816988"
        packed = "5d6f1484f6571282790d64821429eeeadee71ba6b6d566088f58370634d2c579"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_3 = {F6 46 03 02 75 5? 8B 46 10 40 50 E8 [4] 8B D8 89 5C 24 1C 85 DB 74 41 F6 46 03 01 74 53 8B 46 10 89 44 24 1C 8B 46 0C 53 03 C7 E8 [4] 59}
        $crypto32_4 = {C7 44 24 10 01 00 00 00 8B 4E 10 C6 04 08 00 8B 4D ?? 89 01 8B 46 ?? 8B 4D ?? 89 01 8B 44 24 10 5F 5E 5B 8B E5 5D C2 0C 00}
        $cpuid = {8B C4 FF 18 8B F0 33 C0 0F A2 66 8C D8 66 8E D0 8B E5 8B C6 5E 5B 5D C3}
    condition:
        any of ($crypto32*) and $cpuid
}
rule Varenyky
{
    meta:
        author = "kevoreilly"
        description = "Varenyky Payload"
        cape_type = "Varenyky Payload"
    strings:
        $onion = "jg4rli4xoagvvmw47fr2bnnfu7t2epj6owrgyoee7daoh4gxvbt3bhyd.onion"
    condition:
        uint16(0) == 0x5A4D and ($onion)
}
rule VBCrypter
{
    meta:
        author = "kevoreilly"
        description = "VBCrypter anti-hook Bypass"
        cape_options = "bp0=$antihook-12,action0=jmp,count=0"
    strings:
        $antihook = {43 39 C3 0F 84 ?? 00 00 00 80 3B B8 75 ?? 83 7B 01 00 75 ?? 80 7B 05 BA 75 ?? 8B 53 06 83 C3 0A 31 C9}
    condition:
        any of them
}
rule Vidar
{
    meta:
        author = "kevoreilly,rony"
        description = "Vidar Payload"
        cape_type = "Vidar Payload"
        packed = "0cff8404e73906f3a4932e145bf57fae7a0e66a7d7952416161a5d9bb9752fd8"
    strings:
        $decode = {FF 75 0C 8D 34 1F FF 15 ?? ?? ?? ?? 8B C8 33 D2 8B C7 F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 47 88 06 3B 7D 10 72 D8}
        $xor_dec = {0F B6 [0-5] C1 E? ?? 33 ?? 81 E? [0-5] 89 ?? 7C AF 06}
        $wallet = "*wallet*.dat" fullword ascii wide
        $s1 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii wide
        $s2 = "screenshot.jpg" fullword ascii wide
        $s3 = "\\Local State" fullword ascii wide
        $s4 = "Content-Disposition: form-data; name=\"" fullword ascii wide
        $s5 = "CC\\%s_%s.txt" fullword ascii wide
        $s6 = "History\\%s_%s.txt" fullword ascii wide
        $s7 = "Autofill\\%s_%s.txt" fullword ascii wide
        $s8 = "Downloads\\%s_%s.txt" fullword ascii wide
    condition:
        uint16be(0) == 0x4d5a and 6 of them 
}
rule VMProtectStub
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
}rule WanaCry
{
    meta:
        author = "kevoreilly"
        description = "WanaCry Payload"
        cape_type = "WanaCry Payload"
    strings:
        $exename    = "@WanaDecryptor@.exe"
        $res        = "%08X.res"
        $pky        = "%08X.pky"
        $eky        = "%08X.eky"
        $taskstart  = {8B 35 58 71 00 10 53 68 C0 D8 00 10 68 F0 DC 00 10 FF D6 83 C4 0C 53 68 B4 D8 00 10 68 24 DD 00 10 FF D6 83 C4 0C 53 68 A8 D8 00 10 68 58 DD 00 10 FF D6 53}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
rule Webshell_in_image
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
}// Operation Windigo yara rules
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
rule Windows_Credentials_Editor
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
}rule XenoRAT {
   meta:
      description = "Detects XenoRAT"
      author = "Any.Run"
      reference = "https://github.com/moom825/xeno-rat"
      date = "2024-01-13"
      
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

      $s1 = "SELECT * FROM AntivirusProduct" fullword wide
      $s2 = "SELECT * FROM Win32_OperatingSystem" fullword wide
      $s3 = "WindowsUpdate" fullword wide
      $s4 = "HWID" fullword ascii
      $s5 = "AddToStartupNonAdmin" ascii
      $s6 = "CreateSubSock" ascii
      $s7 = "Badapplexe Executor from github important" fullword wide
      $s8 = "mutex_string" fullword ascii
      $s9 = "_EncryptionKey" fullword ascii
      $s10 = "/query /v /fo csv" fullword wide
      $s11 = "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>" wide
      $s12 = "/C choice /C Y /N /D Y /T 3 & Del \"" fullword wide
      

   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      (1 of ($x*) or 7 of them)
}


rule XenoRAT_server {
   meta:
      description = "Detects XenoRAT server"
      author = "Any.Run"
      reference = "https://github.com/moom825/xeno-rat"
      date = "2024-01-17"
      
      hash1 = "020D6667BE8E017E0B432B228A9097CFFE9E5CA248EECAF566151E4E2BD7195B" 
      hash2 = "B61E4D30AF50474AED593EC748E4A88875A7B492A319EDC2FD44B9F51B094769"
           
      url1 = "https://app.any.run/tasks/95ab175f-88d8-4e9e-9283-8e0fe2a7335c"
      url2 = "https://app.any.run/tasks/b6ad1585-e5e8-49f5-bc36-7fd91e8c9fd8"
      
   strings:
      $x1 = "The name of this tool is xeno-rat. Why is it called that? Well, to be honest, it just sounded nice." ascii fullword
      $x2 = "xeno_rat_server" ascii
      $x3 = "xeno rat server" ascii wide
      $x4 = "Xeno-rat: Created by moom825" wide fullword

      $s1 = "C:\\Windows\\System32\\rundll32.exe shell32.dll,#61" fullword wide
      $s2 = "Hvnc_Load" fullword ascii
      $s3 = "KeyLogger_Load" fullword ascii
      $s4 = "Live Microphone" fullword wide
      $s5 = "Windir + Disk Cleanup" fullword wide
      $s6 = "Uac Bypass" fullword wide
      $s7 = "Current Password: 1234" fullword wide
      $s8 = "plugins\\Hvnc.dll" fullword wide
      $s9 = "hidden_desktop" fullword wide
      $s10 = "moom825" ascii
      
      
   condition:
      uint16(0) == 0x5a4d and
      (1 of ($x*) or 7 of ($s*))
}


rule XiaoBa
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
}rule XWorm
{
    meta:
        author = "kevoreilly"
        description = "XWorm Config Extractor"
        cape_options = "bp0=$decrypt+11,action0=string:r10,count=1,typestring=XWorm Config"
    strings:
        $decrypt = {45 33 C0 39 09 FF 15 [4] 48 8B F0 E8 [4] 48 8B C8 48 8B D6 48 8B 00 48 8B 40 68 FF 50 ?? 90}
    condition:
        any of them
}
rule Zeppelin
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
}rule zeroaccess_css
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "4944324bad3b020618444ee131dce3d0"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "close-mail{right:130px "
	$string1 = "ccc;box-shadow:0 0 5px 1px "
	$string2 = "757575;border-bottom:1px solid "
	$string3 = "777;height:1.8em;line-height:1.9em;display:block;float:left;padding:1px 15px;margin:0;text-shadow:-1"
	$string4 = "C4C4C4;}"
	$string5 = "999;-webkit-box-shadow:0 0 3px "
	$string6 = "header div.service-links ul{display:inline;margin:10px 0 0;}"
	$string7 = "t div h2.title{padding:0;margin:0;}.box5-condition-news h2.pane-title{display:block;margin:0 0 9px;p"
	$string8 = "footer div.comp-info p{color:"
	$string9 = "pcmi-listing-center .full-page-listing{width:490px;}"
	$string10 = "pcmi-content-top .photo img,"
	$string11 = "333;}div.tfw-header a var{display:inline-block;margin:0;line-height:20px;height:20px;width:120px;bac"
	$string12 = "ay:none;text-decoration:none;outline:none;padding:4px;text-align:center;font-size:9px;color:"
	$string13 = "333;}body.page-videoplayer div"
	$string14 = "373737;position:relative;}body.node-type-video div"
	$string15 = "pcmi-content-sidebara,.page-error-page "
	$string16 = "fff;text-decoration:none;}"
	$string17 = "qtabs-list li a,"
	$string18 = "cdn2.dailyrx.com"
condition:
	18 of them
}
rule zeroaccess_css2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "e300d6a36b9bfc3389f64021e78b1503"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "er div.panel-hide{display:block;position:absolute;z-index:200;margin-top:-1.5em;}div.panel-pane div."
	$string1 = "ve.gif) right center no-repeat;}div.ctools-ajaxing{float:left;width:18px;background:url(http://cdn3."
	$string2 = "cdn2.dailyrx.com"
	$string3 = "efefef;margin:5px 0 5px 0;}"
	$string4 = "node{margin:0;padding:0;}div.panel-pane div.feed a{float:right;}"
	$string5 = ":0 5px 0 0;float:left;}div.tweets-pulled-listing div.tweet-authorphoto img{max-height:40px;max-width"
	$string6 = "i a{color:"
	$string7 = ":bold;}div.tweets-pulled-listing .tweet-time a{color:silver;}div.tweets-pulled-listing  div.tweet-di"
	$string8 = "div.panel-pane div.admin-links{font-size:xx-small;margin-right:1em;}div.panel-pane div.admin-links l"
	$string9 = "div.tweets-pulled-listing ul{list-style:none;}div.tweets-pulled-listing div.tweet-authorphoto{margin"
	$string10 = "FFFFDD none repeat scroll 0 0;border:1px solid "
	$string11 = "vider{clear:left;border-bottom:1px solid "
condition:
	11 of them
}
rule zeroaccess_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "0e7d72749b60c8f05d4ff40da7e0e937"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "screen.height:"
	$string1 = "</script></head><body onload"
	$string2 = "Fx0ZAQRKXUVgbh0qNDRJVxYwGg4tGh8aHQoAVQQSNyo0NElXFjAaDi0NFQYESl1FBBNnTFoSPiBmADwnPTQxPSdKWUUEE2UcGR0z"
	$string3 = "0);-10<b"
	$string4 = "function fl(){var a"
	$string5 = "0);else if(navigator.mimeTypes"
	$string6 = ");b.href"
	$string7 = "/presults.jsp"
	$string8 = "128.164.107.221"
	$string9 = ")[0].clientWidth"
	$string10 = "presults.jsp"
	$string11 = ":escape(c),e"
	$string12 = "navigator.plugins.length)navigator.plugins["
	$string13 = "window;d"
	$string14 = "gr(),j"
	$string15 = "VIEWPORT"
	$string16 = "FQV2D0ZAH1VGDxgZVg9COwYCAwkcTzAcBxscBFoKAAMHUFVuWF5EVVYVdVtUR18bA1QdAU8HQjgeUFYeAEZ4SBEcEk1FTxsdUlVA"
condition:
	16 of them
}
rule zeroaccess_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "a9f30483a197cfdc65b4a70b8eb738ab"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Square ad tag  (tile"
	$string1 = "  adRandNum "
	$string2 = " cellspacing"
	$string3 = "\\n//-->\\n</script>"
	$string4 = "format"
	$string5 = "//-->' "
	$string6 = "2287974446"
	$string7 = "NoScrBeg "
	$string8 = "-- start adblade -->' "
	$string9 = "3427054556"
	$string10 = "        while (i >"
	$string11 = "return '<table width"
	$string12 = "</scr' "
	$string13 = " s.substring(0, i"
	$string14 = " /></a></noscript>' "
	$string15 = "    else { isEmail "
	$string16 = ").submit();"
	$string17 = " border"
	$string18 = "pub-8301011321395982"
condition:
	18 of them
}
rule zeroaccess_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "b5fda04856b98c254d33548cc1c1216c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ApiClientConfig"
	$string1 = "function/.test(pa.toString())"
	$string2 = "background-image:url(http:\\/\\/static.ak.fbcdn.net\\/rsrc.php\\/v2\\/y6\\/x\\/s816eWC-2sl.gif)}"
	$string3 = "Music.init"
	$string4 = "',header:'bool',recommendations:'bool',site:'hostname'},create_event_button:{},degrees:{href:'url'},"
	$string5 = "cca6477272fc5cb805f85a84f20fca1d"
	$string6 = "document.createElement('form');c.action"
	$string7 = "javascript:false"
	$string8 = "s.onMessage){j.error('An instance without whenReady or onMessage makes no sense');throw new Error('A"
	$string9 = "NaN;}else h"
	$string10 = "sprintf"
	$string11 = "window,j"
	$string12 = "o.getUserID(),da"
	$string13 = "FB.Runtime.getLoginStatus();if(b"
	$string14 = ")');k.toString"
	$string15 = "rovide('XFBML.Send',{Dimensions:{width:80,height:25}});"
	$string16 = "{log:i};e.exports"
	$string17 = "a;FB.api('/fql','GET',f,function(g){if(g.error){ES5(ES5('Object','keys',false,b),'forEach',true,func"
	$string18 = "true;}}var ia"
condition:
	18 of them
}
rule zeroaccess_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "5f13fdfb53a3e60e93d7d1d7bbecff4f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.createDocumentFragment();img.src"
	$string1 = "typeOf(events)"
	$string2 = "var i,x,y,ARRcookies"
	$string3 = "callbacks.length;j<l;j"
	$string4 = "encodeURIComponent(value);if(options.domain)value"
	$string5 = "event,HG.components.get('windowEvent_'"
	$string6 = "'read'in Cookie){return Cookie.read(c_name);}"
	$string7 = "item;},get:function(name,def){return HG.components.exists(name)"
	$string8 = "){window.addEvent(windowEvents[i],function(){var callbacks"
	$string9 = "reunload:function(callback){HG.events.add('beforeunload',callback);},add:function(event,callback){HG"
	$string10 = "name){if(HG.components.exists(name)){delete HG.componentList[name];}}},util:{uuid:function(){return'"
	$string11 = "window.HG"
	$string12 = "x.replace(/"
	$string13 = "encodeURIComponent(this.attr[key]));}"
	$string14 = "options.domain;if(options.path)value"
	$string15 = "this.page_sid;this.attr.user_sid"
condition:
	15 of them
}
rule zeroaccess_js4
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "268ae96254e423e9d670ebe172d1a444"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ").join("
	$string1 = "JSON.stringify:function(o){if(o"
	$string2 = "){try{var a"
	$string3 = ");return $.jqotecache[i]"
	$string4 = "o.getUTCFullYear(),hours"
	$string5 = "seconds"
	$string6 = "')');};$.secureEvalJSON"
	$string7 = "isFinite(n);},secondsToTime:function(sec_numb){sec_numb"
	$string8 = "')');}else{throw new SyntaxError('Error parsing JSON, source is not valid.');}};$.quoteString"
	$string9 = "o[name];var ret"
	$string10 = "a[m].substr(2)"
	$string11 = ");if(d){return true;}}}catch(e){return false;}}"
	$string12 = "a.length;m<k;m"
	$string13 = "if(parentClasses.length"
	$string14 = "o.getUTCHours(),minutes"
	$string15 = "$.jqote(e,d,t),$$"
	$string16 = "q.test(x)){e"
	$string17 = "{};HGWidget.creator"
condition:
	17 of them
}
rule ZeroT
{
    meta:
        author = "kevoreilly"
        description = "ZeroT Payload"
        cape_type = "ZeroT Payload"
    strings:
        $decrypt = {8B C1 8D B5 FC FE FF FF 33 D2 03 F1 F7 75 10 88 0C 33 41 8A 04 3A 88 06 81 F9 00 01 00 00 7C E0}
        $string1 = "(*^GF(9042&*"
        $string2 = "s2-18rg1-41g3j_.;"
        $string3 = "GET" wide
        $string4 = "open"
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule zerox88_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "cad8b652338f5e3bc93069c8aa329301"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "function gSH() {"
	$string1 = "200 HEIGHT"
	$string2 = "'sh.js'><\\/SCRIPT>"
	$string3 = " 2 - 26;"
	$string4 = "<IFRAME ID"
	$string5 = ",100);"
	$string6 = "200></IFRAME>"
	$string7 = "setTimeout("
	$string8 = "'about:blank' WIDTH"
	$string9 = "mf.document.write("
	$string10 = "document.write("
	$string11 = "Kasper "
condition:
	11 of them
}
rule zerox88_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "9df0ac2fa92e602ec11bac53555e2d82"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " new ActiveXObject(szHTTP); "
	$string1 = " Csa2;"
	$string2 = "var ADO "
	$string3 = " new ActiveXObject(szOx88);"
	$string4 = " unescape("
	$string5 = "/test.exe"
	$string6 = " szEtYij;"
	$string7 = "var HTTP "
	$string8 = "%41%44%4F%44%42%2E"
	$string9 = "%4D%65%64%69%61"
	$string10 = "var szSRjq"
	$string11 = "%43%3A%5C%5C%50%72%6F%67%72%61%6D"
	$string12 = "var METHOD "
	$string13 = "ADO.Mode "
	$string14 = "%61%79%65%72"
	$string15 = "%2E%58%4D%4C%48%54%54%50"
	$string16 = " 7 - 6; HTTP.Open(METHOD, szURL, i-3); "
condition:
	16 of them
}
rule ZeusPanda
{
    meta:
        author = "kevoreilly"
        description = "ZeusPanda Payload"
        cape_type = "ZeusPanda Payload"
    strings:
        $code1 = {8B 01 57 55 55 55 55 55 55 53 51 FF 50 0C 85 C0 78 E? 55 55 6A 03 6A 03 55 55 6A 0A FF 37}
        $code2 = {8D 85 B0 FD FF FF 50 68 ?? ?? ?? ?? 8D 85 90 FA FF FF 68 0E 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 7E ?? 68 04 01 00 00 8D 85 B0 FD FF FF}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
rule zeus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Zeus Exploit Kit Detection"
	hash0 = "c87ac7a25168df49a64564afb04dc961"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var jsmLastMenu "
	$string1 = "position:absolute; z-index:99' "
	$string2 = " -1)jsmSetDisplayStyle('popupmenu' "
	$string3 = " '<tr><td><a href"
	$string4 = "  jsmLastMenu "
	$string5 = "  var ids "
	$string6 = "this.target"
	$string7 = " jsmPrevMenu, 'none');"
	$string8 = "  if(jsmPrevMenu "
	$string9 = ")if(MenuData[i])"
	$string10 = " '<div style"
	$string11 = "popupmenu"
	$string12 = "  jsmSetDisplayStyle('popupmenu' "
	$string13 = "function jsmHideLastMenu()"
	$string14 = " MenuData.length; i"
condition:
	14 of them
}
rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader API Spam Bypass"
        cape_options = "bp0=$trap1-5,action0=hooks:0,bp1=$traps-108,action1=jmp:15,bp2=$traps-88,action2=hooks:1,count=0"
    strings:
        $trap1 = {81 F7 4C 01 00 00 8D B4 37 [2] FF FF 31 FE 69 FE 95 03 00 00 E8 [4] 31 FE 0F AF FE 0F AF FE E8}
        $traps = {6A 44 53 E8 [2] FF FF 83 C4 08 8D 85 ?? FF FF FF C7 85 ?? FF FF FF 44 00 00 00 50}
    condition:
        uint16(0) == 0x5A4D and any of them
}
