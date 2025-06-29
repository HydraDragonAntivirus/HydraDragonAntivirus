import "magic"
rule INFO_ELF_FILE{
	meta:
		version = "1"
		date = "1/8/24"
		modified = "1/8/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Detection of ELF File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "d7efa4eb322759bdeddbfd8345fed9b1"
		hash = "2fa3717308c8e083b6e57fc159f15ccccc430366"
		hash = "fcdd043b1f278ce8cae56e7b651ffe7c0587054f403a8643470b20fc9e05d051"
    condition:
        (magic.type() contains "ELF" or uint32(0) == 0x464c457f)
}		
