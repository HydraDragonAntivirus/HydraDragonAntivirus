import "magic"
rule INFO_HWP_FILE {
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of HWP File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/"
		hash = "c155f49f0a9042d6df68fb593968e110"
		hash = "9d6fa64e0c0f3ec7442cb72bfaa016c3e3d7ff52"
		hash = "81ee247eb8d9116893e5742d12b2d8cd2835db3f751d6be16c2e927b892c5dc7"
  condition:
    magic.type() contains "Hangul (Korean) Word Processor File" 
}
