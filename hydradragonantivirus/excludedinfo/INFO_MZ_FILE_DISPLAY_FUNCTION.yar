import "magic"
rule INFO_MZ_FILE_DISPLAY_FUNCTION{
	meta:
		version = "1"
		date = "2/6/24"
		modified = "2/6/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Checks if there are monitors or resolution limitations with function"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://evasions.checkpoint.com/techniques/generic-os-queries.html"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "GetDesktopWindow" ascii wide 
		$STR2 = "GetWindowRect" ascii wide  
		$STR3 = "GetMonitorInfo" ascii wide 
		$STR4 = "EnumDisplayMonitors" ascii wide 
	condition:
		(magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d) and any of them
}

    
    
