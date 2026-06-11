        import "magic"
        
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
        import "magic"
        
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