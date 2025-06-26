import "vt"
import "magic"
rule infostealer_win_stealc_behaviour {
	meta:
		malware = "Stealc"
		description = "Find Stealc sample based characteristic behaviors"
		source = "SEKOIA.IO"
		reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
		classification = "TLP:CLEAR"
		hash = "3feecb6e1f0296b7a9cb99e9cde0469c98bd96faed0beda76998893fbdeb9411"

	condition:
        for any cmd in vt.behaviour.command_executions : (
        	cmd contains "\\*.dll"
        ) and
        for any cmd in vt.behaviour.command_executions : (
        	cmd contains "/c timeout /t 5 & del /f /q"
        ) and
		for any c in vt.behaviour.http_conversations : (
			c.url contains ".php"
		)
}
rule bumblebee_vhd {
    meta:
        id = "0a9d1ffa-a3ff-4b15-b660-b4c132d5a415"
        version = "1.0"
        description = "BumbleBee new infection vector via VHD file and powershell second stage"
        author = "Sekoia.io"
        creation_date = "2022-09-09"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ascii
        $s2 = "Invalid partition table" ascii
        $s3 = "BOOTMGR" ascii
        $s4 = "LNK" ascii
        
    condition:
        magic.mime_type() == "application/x-virtualbox-vhd" and
        filesize > 3MB and filesize < 10MB and
        all of ($s*)
}

rule icedid_chm_ttp {
    meta:
        id = "cae771d4-a9cf-4325-81b3-c00090cbc05e"
        version = "1.0"
        description = "IcedID campaign delivering ISO file with CHM attack chain"
        author = "Sekoia.io"
        creation_date = "2022-09-28"
        classification = "TLP:CLEAR"
        
    strings:
        $hta1 = "<HTA:APPLICATION " ascii
        $hta2 = "<script language=\"Javascript\">" ascii
        $hta3 = "ActiveXObject" ascii
        $hta4 = "cmd /c rundll32 \\" ascii
        $chm1 = "CHM" ascii
        $chm2 = ".htm" ascii
        
    condition:
        3 of ($hta*) and all of ($chm*) and magic.mime_type() == "application/x-iso9660-image" and filesize > 500KB
}
// I only removed vhash
rule dropper_win_romcom_dropper {
    meta:
        id = "ca1b7114-5a83-4620-a9e2-8228df2be7b1"
        version = "1.0"
        description = "Detect the dropper of RomCom malware"
        author = "Sekoia.io"
        creation_date = "2022-11-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "regInjecttNew.dll"
        
    condition:
        //Strings
        uint16(0)==0x5A4D and all of them

        //Imphash
        or pe.imphash()=="643c3d5c721741ad5b90c98c48007038"

        //Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "1c397f4ddafdcfd12bbc41cae45cdf9f"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "b71dc0007c685c790fb2542ddcf284f4"
        )

        //Vhash
        or vhash=="175076655d155515655038z55?z1"
}