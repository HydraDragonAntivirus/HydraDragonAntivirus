import "magic"
rule INFO_MZ_FILE_HARDWARE_FUNCTION{
	meta:
		version = "1"
		date = "2/5/24"
		modified = "2/5/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Checks if there are hardware limitations with function"
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
		$STR1 = "GetMemoryStatusEx" ascii wide 
		$STR2 = "GetSystemInfo" ascii wide  
		$STR3 = "GetDiskFreeSpaceExA" ascii wide 
		$STR4 = "GetDiskFreeSpaceExW" ascii wide 
	condition:
		(magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d) and any of them
}
