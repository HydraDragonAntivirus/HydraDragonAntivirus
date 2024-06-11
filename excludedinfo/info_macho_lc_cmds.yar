import "macho"

rule info_macho_lc_cmd_encryption_info
{
	meta:
		description = "Identify Mach-O executables that are encrypted (have LC_ENCRYPTION_INFO or LC_ENCRYPTION_INFO_64)."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.31"
		DaysofYARA = "31/100"

	condition:
		(
			uint32be(0) == 0xCFFAEDFE or
			uint32be(0) == 0xCEFAEDFE
		) and
		for any cmd in (0 .. macho.sizeofcmds) : (
			uint32be(cmd) == 0x21000000 or
			uint32be(cmd) == 0x2C000000
		)
}

rule info_macho_lc_cmd_min_version
{
	meta:
		description = "Identify Mach-O executables that specify a minimum version (LC_VERSION_MIN_MACOSX or LC_VERSION_MIN_IPHONEOS)."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.31"
		DaysofYARA = "31/100"

	condition:
		(
			uint32be(0x0) == 0xCFFAEDFE or
			uint32be(0x0) == 0xCEFAEDFE
		) and
		for any cmd in (0 .. macho.sizeofcmds) : (
			uint32be(cmd) == 0x24000000 or
			uint32be(cmd) == 0x25000000
		)
}

rule info_macho_lc_cmd_code_signature
{
	meta:
		description = "Identify Mach-O executables that are signed (has LC_CODE_SIGNATURE)."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.31"
		DaysofYARA = "31/100"

	condition:
		(
			uint32be(0) == 0xCFFAEDFE or
			uint32be(0) == 0xCEFAEDFE
		) and
		for any cmd in (0 .. macho.sizeofcmds) : (
			uint32be(cmd) == 0x1D000000
		)
}
