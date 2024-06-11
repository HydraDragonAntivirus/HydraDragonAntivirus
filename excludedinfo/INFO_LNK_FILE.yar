import "magic"
rule INFO_LNK_FILE {
	meta:
		version = "1"
		date = "1/1/24"
		modified = "1/1/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "https://csirt.ninja/?p=1103"
		author = "@x0rc1sm"
		description = "Detection of LNK File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf"
		hash = "0b6845fbfa54511f21d93ef90f77c8de"
		hash = "cc3b6cafdbb88bd8dac122e73d3d0f067cf63091"
		hash = "6d910cd88c712beac63accbc62d510820f44f630b8281ee8b39382c24c01c5fe"
  condition:
    (magic.type() contains "MS Windows shortcut" or uint16(0)==0x004c) and
    filesize < 10KB 
}
