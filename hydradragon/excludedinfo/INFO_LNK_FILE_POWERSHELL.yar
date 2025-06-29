import "magic"
rule INFO_LNK_FILE_POWERSHELL {
	meta:
		version = "1"
		date = "1/9/24"
		modified = "1//24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = ""
		author = "@x0rc1sm"
		description = "Detection of LNK File Headers/Magic header and containing powershell"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://stairwell.com/resources/the-ink-stained-trail-of-goldbackdoor/"
		hash = "99fb399c9b121ef6e60e9bdff8b324b2"
		hash = "ea0609fbf3bf0cfb2acea989126d8caafe5350ec"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
	strings:
		$s1 = "powershell" ascii wide nocase
		$s2 = "powershell -windowstyle hidden" ascii wide nocase
		$s3 = "powershell.exe" ascii wide nocase
  condition:
    (magic.type() contains "MS Windows shortcut" or uint16(0)==0x004c) and any of them
}
