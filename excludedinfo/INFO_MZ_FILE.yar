import "magic"
rule INFO_MZ_FILE {
	meta:
		version = "1"
		date = "1/3/24"
		modified = "1/3/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Windows Executable File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "n/a"
		hash = "ec8db58467d8e2e2221635c592fcca1a"
		hash = "e0215d156d2dc59b6259fd5ff792dc740626c8fa"
		hash = "aebff5134e07a1586b911271a49702c8623b8ac8da2c135d4d3b0145a826f507"
  condition:
    (magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d)
}
