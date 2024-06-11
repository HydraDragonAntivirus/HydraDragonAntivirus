import "magic"
rule INFO_PDF_FILE_GOOGLE_DOC
{
	meta:
		version = "1"
		date = "1/28/24"
		modified = "1/28/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = ""
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "APT"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = /Skia\/PDF m[0-9]{1,3} Google Docs Renderer/
	condition:
		(magic.type() contains "PDF document" or uint32be(0) == 0x25504446) and $STR1
}
