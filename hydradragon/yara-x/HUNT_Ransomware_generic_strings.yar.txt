rule HUNT_Ransomware_generic_strings {
	meta:
		description = "Matches ransom note strings often found in ransomware binaries."
		last_modified = "2024-01-27"
		author = "@petermstewart"
		DaysofYara = "27/100"

	strings:
		$a1 = "Install TOR Browser" nocase ascii wide
		$a2 = "Download Tor" nocase ascii wide
		$a3 = "decrypt your files" nocase ascii wide
		$a4 = "your company is fully" nocase ascii wide
		$a5 = "recover your files" nocase ascii wide
		$a6 = "files were encrypted" nocase ascii wide
		$a7 = "files will be decrypted" nocase ascii wide
		$a8 = "Contact us" nocase ascii wide
		$a9 = "decrypt 1 file" nocase ascii wide
		$a10 = "has been encrypted" nocase ascii wide
		$a11 = "Contact information" nocase ascii wide
		$a12 = "pay the ransom" nocase ascii wide
		$a13 = "Decryption ID" nocase ascii wide
		$a14 = "are encrypted" nocase ascii wide

	condition:
		(uint16(0) == 0x5a4d or			//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		2 of them
}
