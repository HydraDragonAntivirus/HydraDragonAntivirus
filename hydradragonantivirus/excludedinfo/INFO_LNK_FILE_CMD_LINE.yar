import "magic"
rule INFO_LNK_FILE_CMD_LINE {
	meta:
		version = "1"
		date = "1/9/24"
		modified = "1//24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = ""
		author = "@x0rc1sm"
		description = "Detection of LNK File Headers/Magic header and containing CMD.EXE"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://blog.eclecticiq.com/mustang-panda-apt-group-uses-european-commission-themed-lure-to-deliver-plugx-malware"
		hash = "67c8b4f7e6e79f9747e38163ad69a3fb"
		hash = "3c039fbf5215da7c2f3be18831da7a35a8f168b6"
		hash = "2c0273394cda1b07680913edd70d3438a098bb4468f16eebf2f50d060cdf4e96"
	strings:
		$s1 = "C:\\Windows\\System32\\cmd.exe" ascii wide nocase
		$s2 = "cmd.exe" ascii wide nocase
  condition:
    (magic.type() contains "MS Windows shortcut" or uint16(0)==0x004c) and any of them
}
