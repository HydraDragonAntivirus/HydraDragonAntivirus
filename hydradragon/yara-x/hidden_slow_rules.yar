import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "macho"
import "math"
import "time"


// YARA rule set for detecting potential malicious TTPs in a file sample
// Author: Phil Stokes, SentinelLabs
// Date: 29 August, 2023
// Ref: https://s1.ai/BigBins-macOS

rule maldoc_indirect_function_call_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
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

rule Embedded_EXE_Cloaking : maldoc {
    meta:
        description = "Detects an embedded executable in a non-executable file"
        author = "Florian Roth"
        date = "2015/02/27"
        score = 80
    strings:
        $noex_png = { 89 50 4E 47 }
        $noex_pdf = "%PDF"
        $noex_rtf = "{\\rtf1"
        $noex_jpg = { FF D8 FF E0 }
        $noex_gif = "GIF8"
        $mz  = "MZ"
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

rule CrowdStrike_PutterPanda_01 : fourh_stack_strings putterpanda
	{
	meta:
		description = "PUTTER PANDA - 4H RAT"
                author = "CrowdStrike"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
		yara_version = ">=1.6"
	
	strings:
	    $key_combined_1 = { C6 44 24 ?? 34 C6 44 24 ?? 36 C6 44 24 ?? 21 C6 44 24 ?? 79 C6 44 24 ?? 6F C6 44 24 ?? 00 }
	
	
	    // ebp
	    $keyfrag_ebp_1 = { C6 45 ?? 6C }    // ld66!yo
	    $keyfrag_ebp_2 = { C6 45 ?? 64 } 
	    $keyfrag_ebp_3 = { C6 45 ?? 34 }
	    $keyfrag_ebp_4 = { C6 45 ?? 36 }
	    $keyfrag_ebp_5 = { C6 45 ?? 21 }
	    $keyfrag_ebp_6 = { C6 45 ?? 79 }
	    $keyfrag_ebp_7 = { C6 45 ?? 6F }
	
	    // esp
	    $keyfrag_esp_1 = { c6 44 ?? 6C }    // ld66!yo
	    $keyfrag_esp_2 = { c6 44 ?? 64 }
	    $keyfrag_esp_3 = { c6 44 ?? 34 }
	    $keyfrag_esp_4 = { c6 44 ?? 36 }
	    $keyfrag_esp_5 = { c6 44 ?? 21 }
	    $keyfrag_esp_6 = { c6 44 ?? 79 }
	    $keyfrag_esp_7 = { c6 44 ?? 6F }
	
	    // reduce FPs by checking for some common strings
	    $check_zeroes = "0000000"
	    $check_param = "Invalid parameter"
	    $check_ercv = "ercv= %d"
	    $check_unk = "unknown"
	
	condition:
	    any of ($key_combined*) or 
	    (1 of ($check_*) and
	        (
	            (
	                all of ($keyfrag_ebp_*) and
	                for any i in (1..#keyfrag_ebp_5) : (
	                    for all of ($keyfrag_ebp_*): ($ in (@keyfrag_ebp_5[i]-100..@keyfrag_ebp_5[i]+100))
	                )
	            )
	            or
	            (
	                for any i in (1..#keyfrag_esp_5) : (
	                    for all of ($keyfrag_esp_*): ($ in (@keyfrag_esp_5[i]-100..@keyfrag_esp_5[i]+100))
	                )
	            )
	        )
	    )
	}

rule MAL_Winnti_BR_Report_MockingJay {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
  strings:
    $load_magic = { C7 44 ?? ?? FF D8 FF E0 }
    $iter = { E9 EA EB EC ED EE EF F0 }
    $jpeg = { FF D8 FF E0 00 00 00 00 00 00 }
  condition:
    uint16(0) == 0x5a4d and
      $jpeg and
      ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and
      for any i in (1..#jpeg): ( uint8(@jpeg[i] + 11) != 0 )
}
rule CrowdStrike_P2P_Zeus
{
    meta:
        copyright       = "CrowdStrike, Inc"
        author          = "Crowdstrike, Inc"
        description     = "P2P Zeus (Gameover)"
        version         = "1.0"
        last_modified   = "2013-11-21"
        actor           = "Gameover Spider"
        malware_family  = "P2P Zeus"
        in_the_wild     = true

    condition:
        for any i in (0..filesize) : (
            uint32(i) ^ uint32(i+4)  == 0x00002606  and
            uint32(i) ^ uint32(i+8)  == 0x31415154  and
            uint32(i) ^ uint32(i+12) == 0x00000a06  and
            uint32(i) ^ uint32(i+16) == 0x00010207  and
            uint32(i) ^ uint32(i+20) == 0x7cf1aa2d  and
            uint32(i) ^ uint32(i+24) == 0x4390ca7b  and
            uint32(i) ^ uint32(i+28) == 0xa96afd9d  and
            uint32(i) ^ uint32(i+32) == 0x0b039138  and
            uint32(i) ^ uint32(i+36) == 0xb3e50578  and
            uint32(i) ^ uint32(i+40) == 0x896eaf36  and
            uint32(i) ^ uint32(i+44) == 0x37a3f8c9  and
            uint32(i) ^ uint32(i+48) == 0xb1c31bcb  and
            uint32(i) ^ uint32(i+52) == 0xcb58f22c  and
            uint32(i) ^ uint32(i+56) == 0x00491be8  and
            uint32(i) ^ uint32(i+60) == 0x0a2a748f
        )
}
rule days_of_yara_url_3byte 
{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  strings:
    $target_string = /https:\/\/github\.com\/100DaysofYARA/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == 0x18074e
      and not for 0x1c4172e j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x1c4172d j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}
rule days_of_yara_url_4byte 
{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  strings:
    $target_string = /https:\/\/github\.com\/100DaysofYARA/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == 0x1b4e5b5f
      and not for 0x1248ee582 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24 ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x1248ee581 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24 ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}
rule current_version_2byte
{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  strings:
    $target_string = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
        uint16be(i) ^ uint16be(i+2) == 0x351b
        and not for 0x2a153 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28, i+30, i+32, i+34, i+36, i+38, i+40 ) : ( 
            uint16be(j) ^ uint16be(j+2) 
        )
        and for 0x2a152 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28, i+30, i+32, i+34, i+36, i+38, i+40 ) : ( uint16be(j) ^ uint16be(j+2) )
    )
}
rule current_version_3byte 
{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  strings:
    $target_string = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == 0x271807
      and not for 0x21267b9 j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24, i+27, i+30, i+33, i+36, i+39 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x21267b8 j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24, i+27, i+30, i+33, i+36, i+39 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}
rule current_version_4byte 
{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  strings:
    $target_string = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == 0x240e1411
      and not for 0x113ecb50a j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24, i+28, i+32, i+36 ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x113ecb509 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24, i+28, i+32, i+36 ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}
rule SUSP_MSF_script
{
	meta:
		author = "Silas Cutler"
		description = "Experimental detection for Metasploit resource scripts"
		date = "2023-01-02"
		version = "1.0"
		ref = "https://docs.rapid7.com/metasploit/resource-scripts/"
		DaysofYARA = "2/100"
	strings:
		$ = "use multi/handler" nocase
		$ = "set payload " nocase
		$ = "set lhost " nocase
		$ = "set lport " nocase
		$ = "set rhost " nocase
		$ = "set rport " nocase
		$ = "exploit" nocase		
	condition:
	 	2 of them and
		for all offset in (0..(filesize-1)): ( uint8(offset) < 127)
}
rule maldoc_indirect_function_call_10
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}
/*
XORSearch wildcard rule(s):
    Indirect function call bis:10:FFB5(B;A???????)(B;B???????)(B;C???????)(B;D???????)FF95(B;A???????)(B;B???????)(B;C???????)(B;D???????)
*/
rule maldoc_find_kernel32_base_method_20
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}
/*
XORSearch wildcard rule(s):
    Find kernel32 base method 3:10:6830000000(B;01011A??)648B(B;00B??A??)
*/
rule maldoc_find_kernel32_base_method_30
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}
/*
XORSearch wildcard rule(s):
    GetEIP method 1:10:E800000000(B;01011???)
*/
rule GregsChallengeReductor
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "A reductor rule for Greg's workflow writeup challenge"
        version = "1.0"
        date = "2023-03-03"
        sha256="4e2d038e9d72ee4d660755ba973a31471dda167d1a51bfdfe60abb2b3de78ba1"
    strings:
        $const_1 = { 24 95 73 C2 48 } // 0x48C27395
        $const_2 = { FF FF FF 7F }    // 0x7FFFFFFF
        $pdb_start = "C:\\git_kraken_repo\\reductor-dev" 
        $mtx1 = "Global\\$$wrk_ls"
        $mtx2 = "Global\\$$wrk_ff"
        $mtx3 = "Global\\$$wrk_cr"
    condition:
        for all i in ( 1..#const_1 ) : ( $const_2 in ( @const_1[i]..@const_1[i]+10) ) // Find the two constants next to each other
        or all of ($mtx*) 
        or $pdb_start
}
rule Heuristic_Stack_String_SeLoadDriverPrivilege_C {
    meta:
        description = "Detects the stack string SeLoadDriverPrivilege being loaded in a combination of 1, 2, and 4 byte chunks, not necessarily in order"
        author = "BitsOfBinary"
        reference = "https://bitsofbinary.github.io/yara/2023/04/08/100daysofyara-day-98.html"
        version = "1.0"
        date = "2023-04-08"
        DaysofYARA = "98/100"
    strings:
        $one_byte_mov_S_stack = {C6 44 24 ?? 53}
        $one_byte_mov_e_stack = {C6 44 24 ?? 65}
        $one_byte_mov_L_stack = {C6 44 24 ?? 4c}
        $one_byte_mov_o_stack = {C6 44 24 ?? 6f}
        $one_byte_mov_a_stack = {C6 44 24 ?? 61}
        $one_byte_mov_d_stack = {C6 44 24 ?? 64}
        $one_byte_mov_D_stack = {C6 44 24 ?? 44}
        $one_byte_mov_r_stack = {C6 44 24 ?? 72}
        $one_byte_mov_i_stack = {C6 44 24 ?? 69}
        $one_byte_mov_v_stack = {C6 44 24 ?? 76}
        $one_byte_mov_P_stack = {C6 44 24 ?? 50}
        $one_byte_mov_l_stack = {C6 44 24 ?? 6c}
        $one_byte_mov_g_stack = {C6 44 24 ?? 67}
        $two_byte_mov_Se_stack = {66 C7 44 24 ?? 53 65}
        $two_byte_mov_eL_stack = {66 C7 44 24 ?? 65 4c}
        $two_byte_mov_Lo_stack = {66 C7 44 24 ?? 4c 6f}
        $two_byte_mov_oa_stack = {66 C7 44 24 ?? 6f 61}
        $two_byte_mov_ad_stack = {66 C7 44 24 ?? 61 64}
        $two_byte_mov_dD_stack = {66 C7 44 24 ?? 64 44}
        $two_byte_mov_Dr_stack = {66 C7 44 24 ?? 44 72}
        $two_byte_mov_ri_stack = {66 C7 44 24 ?? 72 69}
        $two_byte_mov_iv_stack = {66 C7 44 24 ?? 69 76}
        $two_byte_mov_ve_stack = {66 C7 44 24 ?? 76 65}
        $two_byte_mov_er_stack = {66 C7 44 24 ?? 65 72}
        $two_byte_mov_rP_stack = {66 C7 44 24 ?? 72 50}
        $two_byte_mov_Pr_stack = {66 C7 44 24 ?? 50 72}
        $two_byte_mov_vi_stack = {66 C7 44 24 ?? 76 69}
        $two_byte_mov_il_stack = {66 C7 44 24 ?? 69 6c}
        $two_byte_mov_le_stack = {66 C7 44 24 ?? 6c 65}
        $two_byte_mov_eg_stack = {66 C7 44 24 ?? 65 67}
        $two_byte_mov_ge_stack = {66 C7 44 24 ?? 67 65}
        $four_byte_mov_SeLo_stack = {C7 44 24 ?? 53 65 4c 6f}
        $four_byte_mov_eLoa_stack = {C7 44 24 ?? 65 4c 6f 61}
        $four_byte_mov_Load_stack = {C7 44 24 ?? 4c 6f 61 64}
        $four_byte_mov_oadD_stack = {C7 44 24 ?? 6f 61 64 44}
        $four_byte_mov_adDr_stack = {C7 44 24 ?? 61 64 44 72}
        $four_byte_mov_dDri_stack = {C7 44 24 ?? 64 44 72 69}
        $four_byte_mov_Driv_stack = {C7 44 24 ?? 44 72 69 76}
        $four_byte_mov_rive_stack = {C7 44 24 ?? 72 69 76 65}
        $four_byte_mov_iver_stack = {C7 44 24 ?? 69 76 65 72}
        $four_byte_mov_verP_stack = {C7 44 24 ?? 76 65 72 50}
        $four_byte_mov_erPr_stack = {C7 44 24 ?? 65 72 50 72}
        $four_byte_mov_rPri_stack = {C7 44 24 ?? 72 50 72 69}
        $four_byte_mov_Priv_stack = {C7 44 24 ?? 50 72 69 76}
        $four_byte_mov_rivi_stack = {C7 44 24 ?? 72 69 76 69}
        $four_byte_mov_ivil_stack = {C7 44 24 ?? 69 76 69 6c}
        $four_byte_mov_vile_stack = {C7 44 24 ?? 76 69 6c 65}
        $four_byte_mov_ileg_stack = {C7 44 24 ?? 69 6c 65 67}
        $four_byte_mov_lege_stack = {C7 44 24 ?? 6c 65 67 65}
    condition:
        for any of ($four_byte_*) : (
            any of ($one_byte_*, $two_byte_*) at @+8
        )
}rule Reflective_Loader_Shellcode_Base64_Encoded {
    meta:
        author = "BitsOfBinary"
        description = "Detects Base64 encoded reflective loader shellcode stub, seen for example in Meterpreter samples"
        reference = "https://bitsofbinary.github.io/yara/2023/02/02/100daysofyara-day-33.html"
        version = "1.0"
        date = "2023-02-02"
        DaysofYARA = "33/100"
        hash = "ed48d56a47982c3c9b39ee8859e0b764454ab9ac6e7a7866cdef5c310521be19"
        hash = "76d54a57bf9521f6558b588acd0326249248f91b27ebc25fd94ebe92dc497809"
        hash = "1db32411a88725b259a7f079bdebd5602f11130f71ec35bec9d18134adbd4352"
    strings:
        // pop     r10
        // push    r10
        // push    rbp
        // mov     rbp, rsp
        // sub     rsp, 20h
        // and     rsp, 0FFFFFFFFFFFFFFF0h
        // call    $+5
        // pop     rbx
        $ = "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x83\xE4\xF0\xE8\x00\x00\x00\x00\x5B" base64 base64wide
    condition:
        any of them
}rule Heuristic_OneNote_Notebook_with_Embedded_Executable_File {
    meta:
        author = "BitsOfBinary"
        description = "Detects OneNote notebooks with suspicious embedded executable files"
        reference = "https://interoperability.blob.core.windows.net/files/MS-ONE/%5bMS-ONE%5d.pdf"
        reference = "https://www.proofpoint.com/uk/blog/threat-insight/onenote-documents-increasingly-used-to-deliver-malware"
        version = "1.0"
        date = "2023-03-15"
        DaysofYARA = "74/100"
    strings:
        $embedded_file_container = {9B 1D 00 20}
        $embedded_file_name = {9C 1D 00 1C}
        $ext1 = ".ade" ascii wide nocase
        $ext2 = ".adp" ascii wide nocase
        $ext3 = ".ai" ascii wide nocase
        $ext4 = ".bat" ascii wide nocase
        $ext5 = ".chm" ascii wide nocase
        $ext6 = ".cmd" ascii wide nocase
        $ext7 = ".com" ascii wide nocase
        $ext8 = ".cpl" ascii wide nocase
        $ext9 = ".dll" ascii wide nocase
        $ext10 = ".exe" ascii wide nocase
        $ext11 = ".hlp" ascii wide nocase
        $ext12 = ".hta" ascii wide nocase
        $ext13 = ".inf" ascii wide nocase
        $ext14 = ".ins" ascii wide nocase
        $ext15 = ".isp" ascii wide nocase
        $ext16 = ".jar" ascii wide nocase
        $ext17 = ".js" ascii wide nocase
        $ext18 = ".jse" ascii wide nocase
        $ext19 = ".lib" ascii wide nocase
        $ext20 = ".lnk" ascii wide nocase
        $ext21 = ".mde" ascii wide nocase
        $ext22 = ".msc" ascii wide nocase
        $ext23 = ".msi" ascii wide nocase
        $ext24 = ".msp" ascii wide nocase
        $ext25 = ".mst" ascii wide nocase
        $ext26 = ".nsh" ascii wide nocase
        $ext27 = ".pif" ascii wide nocase
        $ext28 = ".ps" ascii wide nocase
        $ext29 = ".ps1" ascii wide nocase
        $ext30 = ".reg" ascii wide nocase
        $ext31 = ".scr" ascii wide nocase
        $ext32 = ".sct" ascii wide nocase
        $ext33 = ".shb" ascii wide nocase
        $ext34 = ".shs" ascii wide nocase
        $ext35 = ".sys" ascii wide nocase
        $ext36 = ".vb" ascii wide nocase
        $ext37 = ".vbe" ascii wide nocase
        $ext38 = ".vbs" ascii wide nocase
        $ext39 = ".vxd" ascii wide nocase
        $ext40 = ".wsc" ascii wide nocase
        $ext41 = ".wsf" ascii wide nocase
        $ext42 = ".wsh" ascii wide nocase
    condition:
        uint32be(0) == 0xE4525C7B and 
        $embedded_file_container and
        for any i in (1 .. #embedded_file_container) : (
            $embedded_file_name in (@embedded_file_container[i] .. @embedded_file_container[i] + 0x30) and
            any of ($ext*) in (@embedded_file_container[i] .. @embedded_file_container[i] + 0x100)
        )
}
rule VOLEXITY_Apt_Ico_Uta0040_B64_C2 : UTA0040 FILE
{
	meta:
		description = "Detection of malicious ICO files used in 3CX compromise."
		author = "threatintel@volexity.com"
		id = "1efb6376-a362-5f03-b4d3-08cd7d634de6"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/2023/2023-03-30 3CX/indicators/rules.yar#L1-L31"
		license_url = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/LICENSE.txt"
		logic_hash = "2667a36ce151c6e964f9ce9a6f587eedbffdd6ec76e451a23c5cfdd08248d15e"
		score = 75
		quality = 80
		tags = "UTA0040, FILE"
		hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$IEND_dollar = {49 45 4e 44 ae 42 60 82 24}
		$IEND_nodollar = {49 45 4e 44 ae 42 60 82 }

	condition:
		uint16be(0)==0x0000 and filesize <120KB and ($IEND_dollar in ( filesize -500.. filesize ) and not $IEND_nodollar in ( filesize -20.. filesize ) and for any k in (1..#IEND_dollar) : ( for all i in (1..4) : ( uint8(@IEND_dollar[k]+!IEND_dollar[k]+i)<123 and uint8(@IEND_dollar[k]+!IEND_dollar[k]+i)>47)))
}
rule VOLEXITY_Apt_Webshell_Aspx_Glasstoken : UTA0178 FILE MEMORY
{
	meta:
		description = "Detection for a custom webshell seen on external facing server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
		author = "threatintel@volexity.com"
		id = "5d96294c-aa61-5752-ab06-d5b27f6ac3a1"
		date = "2023-12-12"
		modified = "2024-01-09"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L24-L49"
		license_url = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/LICENSE.txt"
		logic_hash = "34844dc2ba4b18b25dcb5b14b7b80ec655595c9638600a0f2a6367610c542dd1"
		score = 75
		quality = 80
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9994
		version = 5

	strings:
		$s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
		$re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

	condition:
		for any i in (0..#s1) : ($re in (@s1[i]..@s1[i]+512))
}
rule VOLEXITY_Webshell_Php_Str_Replace_Create_Func : WEBSHELLS GENERAL FILE
{
	meta:
		description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
		author = "threatintel@volexity.com"
		id = "e0a5965c-54c3-5699-a45b-58f7152574dd"
		date = "2022-04-04"
		modified = "2022-07-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L45-L73"
		license_url = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/LICENSE.txt"
		logic_hash = "6a9ded1f1a8e4b8ae5f3db06f71bec6e9f62b6126b7444408d6319a35ed23827"
		score = 75
		quality = 80
		tags = "WEBSHELLS, GENERAL, FILE"
		hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 0

	strings:
		$php = "<?php"
		$s = "=str_replace(" ascii
		$anon_func = "(''," ascii

	condition:
		filesize <100KB and $php at 0 and for any i in (1..#s) : ( for any j in (1..#anon_func) : ( uint16be(@s[i]-2)== uint16be(@anon_func[j]-2)))
}
rule RUSSIANPANDA_Check_Installed_Software : FILE
{
	meta:
		description = "No description has been set in the source file - RussianPanda"
		author = "RussianPanda"
		id = "a45c7012-dc83-59da-a691-251f0a06be12"
		date = "2024-01-14"
		modified = "2024-01-15"
		reference = "https://unprotect.it/technique/checking-installed-software/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Techniques/check_installed_software.yar#L1-L19"
		license_url = "N/A"
		hash = "db44d4cd1ea8142790a6b26880b41ee23de5db5c2a63afb9ee54585882f1aa07"
		logic_hash = "ab079f1edaffca5bce1e872d6e4fc44f7c22b9260feaed7cd38e578646d420ef"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$d1 = "DisplayVersion"
		$u1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
		$reg = "RegOpenKeyExA"
		$h = {68 (01|02) 00 00 80}

	condition:
		uint16(0)==0x5A4D and $reg and $h and for any i in (1..#u1) : ($d1 in (@u1[i]-200..@u1[i]+200))
}
rule ELCEEF_EICAR_Encrypted_ZIP
{
	meta:
		description = "Detects EICAR file in any encrypted ZIP archive"
		author = "marcin@ulikowski.pl"
		id = "c12d42de-356a-584b-9c48-71e65940f1cf"
		date = "2022-12-13"
		modified = "2022-12-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/ff4396e33ef3e2561191a2193902d1d809a7fa3d/rules/EICAR_Encrypted_ZIP.yara#L14-L44"
		license_url = "https://github.com/elceef/yara-rulz/blob/ff4396e33ef3e2561191a2193902d1d809a7fa3d/LICENSE"
		logic_hash = "56851056671bde38338bd200d9fde59c042f35a2cd84ac9401e716f376c9502c"
		score = 75
		quality = 75
		tags = ""

	strings:
		$local = {
			50 4b 03 04 // local file header signature (PK)
			?? 00 // minimum version
			?? 00 // flags (bit 0 and 6 indicate encryption)
			?? 00 // compression method
			?? ?? // last modification time
			?? ?? // last modification date
			?? ?? ?? ?? // CRC-32 of uncompressed and unencrypted data
			?? ?? ?? ?? // compressed size
			?? ?? ?? ?? // uncompressed size
			}

	condition:
		for any i in (1..#local) : (( uint8(@local[i]+6)&0x01 or uint8(@local[i]+6)&0x40) and uint32(@local[i]+14)==0x6851cf3c and uint32(@local[i]+22)==68)
}

rule SIGNATURE_BASE_MAL_Winnti_BR_Report_Mockingjay : FILE
{
	meta:
		description = "Detects Winnti samples"
		author = "@br_data repo"
		id = "9aff9d65-3827-59de-9dc3-38f227155d3d"
		date = "2019-07-24"
		modified = "2023-12-05"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_br.yar#L30-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7a63b6f10cc5feebba16e585cb29d741876e1dc7f4dde3ef43ac76db9c7ad135"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$load_magic = { C7 44 ?? ?? FF D8 FF E0 }
		$iter = { E9 EA EB EC ED EE EF F0 }
		$jpeg = { FF D8 FF E0 00 00 00 00 00 00 }

	condition:
		uint16(0)==0x5a4d and $jpeg and ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and for any i in (1..#jpeg) : ( uint8(@jpeg[i]+11)!=0)
}

rule Dotnet_Hidden_Executables_Detect {
    meta:
        author = "Mehmet Ali Kerimoglu (@CYB3RMX)"
        description = "This rule detects hidden PE file presence."
        reference = "https://github.com/CYB3RMX/Qu1cksc0pe"
        date = "14/04/2023"
    strings:
        $pattern1 = "4D!5A!90" nocase wide ascii
        $pattern2 = "4D-5A-90O" nocase wide ascii
        $pattern3 = "4D5A9ZZZ" nocase wide ascii
        $pattern4 = "~~~9A5D4" nocase wide ascii
        $pattern5 = "09~A5~D4" nocase wide ascii
        $pattern6 = "09}A5}D4" nocase wide ascii
        $pattern7 = "WP09PA5PD4" nocase wide ascii
        $pattern8 = "X-09-A5-D4" nocase wide ascii
        $pattern9 = "ZZ-09-A5-D4" nocase wide ascii
        $hexpat1 = "tema"
        $hexpat2 = { 90 5A 4D }
        $hexpat3 = "erPx"
        $hexpat4 = { F8 AF CF C0 }
        $hexpat5 = { AB F4 DB BF }
    condition:
        ((any of ($pattern*)) or (all of ($hexpat*)))
}rule Embedded_PE
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "Discover embedded PE files, without relying on easily stripped/modified header strings."
    strings:
        $mz = { 4D 5A 90 00 } // 4D 5A gives false positives so I changed it to 4D 5A 90 00
    condition:
        for any i in (1..#mz):
        (
            @mz[i] != 0 and uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
        )
}
/*
Copyright 2021 by ditekSHen (https://github.com/ditekshen/detection).

The 2-Clause BSD License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
rule apt_win_powerstar : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        description = "Custom PowerShell backdoor used by Charming Kitten."
        date = "2021-10-13"
        hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $appname = "[AppProject.Program]::Main()" ascii wide // caller for C# code

        $langfilters1 = "*shar*" ascii wide
        $langfilters2 = "*owers*" ascii wide

        $definitions1 = "[string]$language" ascii wide
        $definitions2 = "[string]$Command" ascii wide
        $definitions3 = "[string]$ThreadName" ascii wide
        $definitions4 = "[string]$StartStop" ascii wide

        $sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

    condition:
        $appname or
        all of ($langfilters*) or
        all of ($definitions*) or
        $sess
}rule apt_ico_uta0040_b64_c2 : UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of malicious ICO files used in 3CX compromise."
        date = "2023-03-30"
        hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $IEND_dollar = {49 45 4e 44 ae 42 60 82 24} // IEND.B`.$
        $IEND_nodollar = {49 45 4e 44 ae 42 60 82 } // IEND.B`.

    condition:
        uint16be(0) == 0x0000 and
        filesize < 120KB and
        (
            $IEND_dollar in (filesize-500..filesize) and not
            $IEND_nodollar in (filesize-20..filesize) and
            for any k in (1..#IEND_dollar):
                (
                for all i in (1..4):
                    (
                        // in range [0-9a-zA-Z]
                        uint8(@IEND_dollar[k]+!IEND_dollar[k] + i ) < 123 and
                        uint8(@IEND_dollar[k]+!IEND_dollar[k] + i) > 47
                    )
                )
        )
}

rule webshell_php_str_replace_create_func : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
        date = "2022-04-04"
        hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $php = "<?php"
        // $P=str_replace(
        $s = "=str_replace(" ascii
        // call it as a function
        // $S=$P('',$a);
        $anon_func = "(''," ascii
        
    condition:
        filesize < 100KB and 
        $php at 0 and
        for any i in (1..#s):
            (
                for any j in (1..#anon_func):
                    (
					    uint16be(@s[i]-2) == uint16be(@anon_func[j]-2)
					)
            )
}
private rule macho_entitlehash
{
	meta:
		description = "Identify code signed entitlements in Mach-o files, then hash them"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them and
		/*
			Entitlements XML stored in:
			@cs_magic_entitlement + 8 -> @cs_magic_entitlement + uint32be(@cs_magic_entitlement+4)
		*/
		for any i in (1 .. #cs_magic_entitlement) : (
			console.log(
				"Entitlehash: ",
				hash.md5(
					@cs_magic_entitlement[i] + 8,
					@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
				)
			)
		)
}

rule macho_entitlehash_check
{
	meta:
		description = "Identify a specific entitlehash"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them and
		for any i in (1 .. #cs_magic_entitlement) : (
			hash.md5(
				@cs_magic_entitlement[i] + 8,
				@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
			) == "7332589bceacb1d5553a77903020d63f"

		)
}
/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/

rule macho_bad_entitlements
{
	meta:
		description = "Identify security related entitlement strings in Mach-o files, only in the entitlement blob."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.06"
		reference = "https://developer.apple.com/documentation/security/hardened_runtime"
		DaysofYARA = "37/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 7? } private

		$s1 = "com.apple.security.cs.allow-unsigned-executable-memory"
		$s2 = "com.apple.security.cs.disable-library-validation"
		$s3 = "com.apple.security.cs.allow-jit"
		$s4 = "com.apple.security.automation.apple-events"
		$s5 = "com.apple.security.cs.allow-dyld-environment-variables"
		$s6 = "com.apple.security.cs.disable-executable-page-protection"
		$s7 = "com.apple.security.cs.debugger"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of ($cs_magic*) and

		for any i in (1 .. #cs_magic_entitlement) : (
			any of ($s*) in ((@cs_magic_entitlement[i] + 8) .. @cs_magic_entitlement[i] + 8 + uint32be(@cs_magic_entitlement[i] + 4))
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
 
/**
This rule is use to match apk virus
**/