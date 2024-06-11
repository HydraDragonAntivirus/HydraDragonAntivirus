import "magic"
rule INFO_RTF_FILE{
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Detection of RTF File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "ca032100ce044e0bc1e0a53263ac68e6"
		hash = "78db48c4a735802ea4b21d638b0f0aa37cca4150"
		hash = "2a533047b555a33bcc5d4ad9fb6f222b601f9d643be908c940c38284aa4354b6"
  condition:
		(magic.type() contains "Rich Text Format" or uint32be(0) == 0x7B5C7274)
}
