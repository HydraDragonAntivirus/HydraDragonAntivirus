import "macho"

rule info_macho_control_flow
{
	meta:
		description = "Identify macho's that have irregular control flow with initializers or terminators using the macho-module"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.27"
		sample = "af7c395426649c57e44eac0bb6c6a109ac649763065ff5b2b23db71839bac655"
		reference = "https://github.com/aidansteele/osx-abi-macho-file-format-reference#table-2-the-sections-of-a__datasegment"
		reference = "https://twitter.com/greglesnewich/status/1618758795743866881"
		DaysofYARA = "27/100"

	condition:
		for any seg in macho.segments : (
			seg.segname == "__DATA" and
			for any sect in seg.sections : (
				(
					sect.sectname == "__mod_init_func" or
					sect.sectname == "__mod_term_func"
				)
			)
		)
}
