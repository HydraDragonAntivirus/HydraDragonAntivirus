import "magic"
rule INFO_PDF_FILE {
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PDF File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.sentinelone.com/blog/malicious-pdfs-revealing-techniques-behind-attacks/"
		hash = "d949720af989e5e492570f0918362867"
		hash = "fddcc1b602f0583833ab549373269ed14e71f0a5"
		hash = "19ac1c943d8d9e7b71404b29ac15f37cd230a463003445b47441dc443d616afd"
  condition:
    (magic.type() contains "PDF document" or uint32be(0) == 0x25504446)
}
