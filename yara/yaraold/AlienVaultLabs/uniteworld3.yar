private rule file_applescript
{
	meta:
		description = "Identify Compiled AppleScript Programs"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.13"
		reference = "https://applescriptlibrary.wordpress.com"
		reference = "https://www.sentinelone.com/labs/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/"
		sample = "b954af3ee83e5dd5b8c45268798f1f9f4b82ecb06f0b95bf8fb985f225c2b6af"
		DaysofYARA = "13/100"

	strings:
		$head = { 46 61 73 64 55 41 53 20 }
		$type = { 61 73 63 72 }
		$tail = { fa de de ad }

	condition:
		$head at 0 and
		$type and
		$tail at filesize - 4
}

private rule file_jxa_script
{
	meta:
		description = "Identify JavaScript for Automation Programs"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.16"
		reference = "https://tylergaw.com/blog/building-osx-apps-with-js/"
		reference = "https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5"
		DaysofYARA = "16/100"

	strings:
		$head = { 4A 73 4F 73 61 44 41 53 }
		$type = { 6A 73 63 72 }
		$tail = { fa de de ad }

	condition:
		$head at 0 and
		$type and
		$tail at filesize - 4
}
private rule file_wasm
{
	meta:
		description = "Identify WebAssembly programs in the binary format."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.17"
		reference = "https://webassembly.github.io/spec/core/binary/index.html"
		sample = "76d82df3b491016136cdc220a0a9e8f686f40aa2"
		DaysofYARA = "17/100"

	strings:
		$head = { 00 61 73 6D 01 00 00 00 }

	condition:
		$head at 0
}
rule head_xar
{
	meta:
		description = "Identify Apple eXtensible ARchive files (.xar, .pkg, .safariextz, .xip, etc)."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.09"
		reference = "https://github.com/apple-oss-distributions/xar"
		DaysofYARA = "9/100"

	condition:
		uint32be(0) == 0x78617221
}
rule hacktool_ezuri
{
	meta:
		description = "Identify an ELF executable written packed with the Ezuri crypter."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.02"
		reference = "https://www.guitmz.com/linux-elf-runtime-crypter/"
		reference = "https://github.com/guitmz/ezuri"
		sample = "ddbb714157f2ef91c1ec350cdf1d1f545290967f61491404c81b4e6e52f5c41f"
		DaysofYARA = "33/100"

	strings:
		$memfd_self = "/proc/self/fd/%d"
		$output = "/dev/null"

		$sym1 = "runFromMemory" // stub/main.go
		$sym2 = "aesDec"        // stub/main.go
		$sym3 = "procName"      // stub/vars.go

	condition:
		uint32(0) == 0x464c457f and // and // ELF
		all of them
}


rule hacktool_shc
{
	meta:
		description = "Identify ELF executables built with the shc compiler"
		author = "@shellcromancer"
		version = "1.1"
		last_modified = "2023.02.01"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "22/100"
		DaysofYARA = "32/100"

	strings:
		$s1 = "neither argv[0] nor"
		$s2 = "%s%s%s: %s"

		$default_expiry = "jahidulhamid@yahoo.com"

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		2 of them
}



rule hacktool_shc_rm_arg
{
	meta:
		description = "Identify executables built with the shc compiler using the rmargs function"
		author = "@shellcromancer"
		version = "1.1"
		last_modified = "2023.02.01"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "23/100"
		DaysofYARA = "32/100"

	strings:
		$rmargs = {
			48 83 7D F8 00 // cmp qword [rbp - 8], 0
			74 ??          // je 0x94
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 8B 00       // mov rax, qword [rax]
			48 85 C0       // test rax, rax
			74 ??          // je 0x88
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 8B 00       // mov rax, qword [rax]
			48 3B 45 F0    // cmp rax, qword [rbp - 0x10]
			75 ??          // jne 0x3d
			EB ??          // jmp 0x79
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 83 C0 08    // add rax, 8
			48 8B 10       // mov rdx, qword [rax]
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 89 10       // mov qword [rax], rdx
			48 83 45 F8 08 // add qword [rbp - 8], 8
			48 83 7D F8 00 // cmp qword [rbp - 8], 0
			74 ??          // je 0x6e
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 8B 00       // mov rax, qword [rax]
			48 85 C0       // test rax, rax
		}

		$clang_0x10000357e = {
			48 83 7d f8 00 //   cmp     qword [rbp-0x8 {var_10}], 0x0
			88 45 ef       //   mov     byte [rbp-0x11 {var_19_1}], al  {0x0}
			0f 84 [4]      //   je      0x1000035b0
			48 8b 4d f8    //   mov     rcx, qword [rbp-0x8 {var_10}]
			31 c0          //   xor     eax, eax  {0x0}
			48 83 39 00    //   cmp     qword [rcx], 0x0
			88 45 ef       //   mov     byte [rbp-0x11 {var_19_1}], al  {0x0}
			0f 84 [4]      //   je      0x1000035b0
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 8b 00       //   mov     rax, qword [rax]
			48 3b 45 f0    //   cmp     rax, qword [rbp-0x10 {var_18}]
			0f 95 c0       //   setne   al
			88 45 ef       //   mov     byte [rbp-0x11 {var_19_1}], al
			8a 45 ef       //   mov     al, byte [rbp-0x11 {var_19_1}]
			a8 01          //   test    al, 0x1
			0f 85 [4]      //   jne     0x1000035c0
			e9 [4]         //   jmp     0x1000035d6
			e9 [4]         //   jmp     0x1000035c5
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 83 c0 08    //   add     rax, 0x8
			48 89 45 f8    //   mov     qword [rbp-0x8 {var_10}], rax
			e9 [4]         //   jmp     0x10000357c
			e9 [4]         //   jmp     0x1000035db
			31 c0          //   xor     eax, eax  {0x0}
			48 83 7d f8 00 //   cmp     qword [rbp-0x8 {var_10}], 0x0
			88 45 ee       //   mov     byte [rbp-0x12 {var_1a_1}], al  {0x0}
			0f 84 [4]      //   je      0x1000035f9
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 83 38 00    //   cmp     qword [rax], 0x0
			0f 95 c0       //   setne   al
			88 45 ee       //   mov     byte [rbp-0x12 {var_1a_1}], al
			8a 45 ee       //   mov     al, byte [rbp-0x12 {var_1a_1}]
			a8 01          //   test    al, 0x1
			0f 85 [4]      //   jne     0x100003609
			e9 [4]         //   jmp     0x100003629
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 8b 48 08    //   mov     rcx, qword [rax+0x8]
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
		}
	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of them
}


rule info_dyld_env_vars
{
	meta:
		description = "Identify executables with environment variables changing the dynamic loader settings. See `man dyld` or `strings /usr/lib/dyld/ | grep DYLD_`"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.07"
		DaysofYARA = "38/100"

	strings:
		$1 = "DYLD_SHARED_REGION"
		$2 = "DYLD_IN_CACHE"
		$3 = "DYLD_JUST_BUILD_CLOSURE"
		$4 = "DYLD_SHARED_CACHE_DIR"
		$5 = "DYLD_PAGEIN_LINKING"
		$6 = "DYLD_FORCE_PLATFORM"
		$7 = "DYLD_SKIP_MAIN"
		$8 = "DYLD_AMFI_FAKE"
		$9 = "DYLD_PRINT_SEGMENTS"
		$10 = "DYLD_PRINT_LIBRARIES"
		$11 = "DYLD_PRINT_BINDINGS"
		$12 = "DYLD_PRINT_INITIALIZERS"
		$13 = "DYLD_PRINT_APIS"
		$14 = "DYLD_PRINT_NOTIFICATIONS"
		$15 = "DYLD_PRINT_INTERPOSING"
		$16 = "DYLD_PRINT_LOADERS"
		$17 = "DYLD_PRINT_SEARCHING"
		$18 = "DYLD_PRINT_ENV"
		$19 = "DYLD_PRINT_TO_STDERR"
		$20 = "DYLD_PRINT_TO_FILE"
		$21 = "DYLD_LIBRARY_PATH"
		$22 = "DYLD_FRAMEWORK_PATH"
		$23 = "DYLD_FALLBACK_FRAMEWORK_PATH"
		$24 = "DYLD_FALLBACK_LIBRARY_PATH"
		$25 = "DYLD_VERSIONED_FRAMEWORK_PATH"
		$26 = "DYLD_VERSIONED_LIBRARY_PATH"
		$27 = "DYLD_INSERT_LIBRARIES"
		$28 = "DYLD_IMAGE_SUFFIX"
		$29 = "DYLD_ROOT_PATH"
		$30 = "DYLD_CLOSURE_DIR"

	condition:
		any of them
}
rule info_macho_python {
  meta:
    description = "Identify Mach-O executables with bundled python content."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.31"
    references = "https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware"
    sample = "1153fca0b395b3f219a6ec7ecfc33f522e7b8fc6676ecb1e40d1827f43ad22be"
    DaysofYARA = "90/100"

  strings:
    $s0 = "@_Py"
    $s1 = "@executable_path/Python"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    #s0 > 10 or $s1
}
rule info_macos_file_metadata
{
  meta:
    description = "Identify macho executable with references to file metadata."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.08"
    DaysofYARA = "98/100"

  strings:
    $cmd0 = "mdls"
    $cmd1 = { 6C 73 [0-6] 20 [0-6] 2D [0-8] 6C [0-8] 40 }

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    uint32(0xc) == 0x2 and  // mach_header->filetype == MH_EXECUTE
    any of them
}
rule info_macos_scpt_applet
{
  meta:
    description = "Identify macOS AppleScript Applet stubs."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.06"
    DaysofYARA = "96/100"

  strings:
    $s0 = "_OpenDefaultComponent"
    $s1 = "_CallComponentDispatch"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    all of them
}
rule susp_macos_xattrs
{
	meta:
		description = "Identify macOS executables that manipulate extended attributes (xattr's)"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.13"
		DaysofYARA = "72/100"

	strings:
		$xattr_quarantine = "com.apple.quarantine"
		$xattr_macl = "com.apple.macl"
		$xattr_provenance = "com.apple.provenance"
		$xattr_sip = "com.apple.rootless"

		$allow_shipitsqrl = "SQRLShipIt"
		$allow_kbfs = "kbfs/libfuse.(*QuarantineXattrHandler)"
		$allow_goupdater = "go-updater/keybase.context.Apply"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		uint32(0xc) == 0x2 and // mach_header->filetype == MH_EXECUTE
		any of ($xattr*) and
		not any of ($allow*)
}
rule info_nop_sled
{
	meta:
		description = "Identify a large region of nop'd bytes."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.07"
		DaysofYARA = "66/100"

	strings:
		// python -c 'print("{ " + "90 " * 100 + "}")'
		$nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of them
}
rule info_padded_dmg
{
  meta:
    description = "Identify Apple DMG with padding between the plist and trailer sections."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.01"
    reference = "https://objective-see.org/blog/blog_0x70.html"
    DaysofYARA = "91/100"

  strings:
    $plist = "</plist>\x0a"

  condition:
    uint32be(filesize - 512) == 0x6b6f6c79 and  // "koly" trailer of DMG
    not $plist at filesize - 521  // trailer is not prefixed by property list
}
rule info_python_nuitka
{
  meta:
    description = "Identify Nuitka-compiled Python executable"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.28"
    reference = "https://nuitka.net"
    DaysofYARA = "87/100"

  strings:
    $nuitka = "nuitka" nocase

  condition:
    (
    int16(0) == 0x5a4d or  // PE
    uint32(0) == 0x464c457f or  // ELF
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and #nuitka > 10
}
rule lang_go_garble
{
	meta:
		description = "Identify a Go binary obfuscated with Garble"
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.11"
		reference = "https://github.com/burrowers/garble"
		DaysofYARA = "11/100"

	strings:
		$GoBuildID = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
		$runtime = "runtime."
		$reflect = "reflect."
		// https://github.com/burrowers/garble/blob/master/hash.go#L172-L178
		$func = /\*func\(\) \*?[a-zA-Z0-9_]{5,20}\.[a-zA-Z0-9_]{4,19}/

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		not $GoBuildID and
		#runtime > 4 and
		#reflect > 4 and
		$func
}

rule lang_python_bytecode
{
  meta:
    description = "Identify Python compiled bytecode"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.27"
    reference = "https://nedbatchelder.com/blog/200804/the_structure_of_pyc_files.html"
    DaysofYARA = "86/100"

  condition:
    uint32be(0) == 0x420D0D0A
}
rule lang_swift
{
	meta:
		description = "Identify a Swift binary regardless of targetting Apple platforms."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.14"
		DaysofYARA = "14/100"

	strings:
		$swift = "__swift"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		#swift >= 4
}
rule lang_zig
{
	meta:
		description = "Identify a Zig binary regardless of format (PE, Macho, ELF) or arch. Tested with regular and stripped binaries."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.04"
		sample = "ae3beacdfaa311d48d9c776ddd1257a6aad2b0fe" // zig init-exe macOS
		DaysofYARA = "4/100"

	strings:
		$zig = "zig"

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		#zig >= 4
}
import "console"
import "hash"

private rule macho_entitlehash
{
	meta:
		description = "Identify code signed entitlements in Mach-o files, then hash them"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them and
		/*
			Entitlements XML stored in:
			@cs_magic_entitlement + 8 -> @cs_magic_entitlement + uint32be(@cs_magic_entitlement+4)
		*/
		for any i in (1 .. #cs_magic_entitlement) : (
			console.log(
				"Entitlehash: ",
				hash.md5(
					@cs_magic_entitlement[i] + 8,
					@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
				)
			)
		)
}

rule macho_entitlehash_check
{
	meta:
		description = "Identify a specific entitlehash"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them and
		for any i in (1 .. #cs_magic_entitlement) : (
			hash.md5(
				@cs_magic_entitlement[i] + 8,
				@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
			) == "7332589bceacb1d5553a77903020d63f"

		)
}
import "math"
import "console"
/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/
rule macho_no_pagezero_no_module
{
	meta:
		description = "Identify macho executable without a __PAGEZERO segment without the module module."
		author = "@shellcromancer"
		version = "1.2"
		date = "2023.03.02"
		sample = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197" // FinSpy
		DaysofYARA = "61/100"

	strings:
		$segment1 = "__PAGEZERO"
		$segment2 = "__ZERO"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		uint32(0xc) == 0x2 and                   // mach_header->filetype == MH_EXECUTE
		not $segment1 in (0 .. uint32(0x14)) and // 0 to mach_header->sizeofcmds
		not $segment2 in (0 .. uint32(0x14))
}
/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/
rule macos_bundle_findersync_appex
{
	meta:
		description = "Identify macOS Finder Sync plugins - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.04.09"
		reference = "https://theevilbit.github.io/beyond/beyond_0026/"
		DaysofYARA = "99/100"

	strings:
		$interface = "FinderSync"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of them
}
// source: /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara
rule XProtect_snowdrift
{
	meta:
		description = "SNOWDRIFT"
	strings:
		$a = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
		$b = "-[Management initCloud:access_token:]"
		$c = "*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.hwp;*.hwpx;*.csv;*.pdf;*.rtf;*.amr;*.3gp;*.m4a;*.txt;*.mp3;*.jpg;*.eml;*.emlx"
	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		2 of them
}

rule mal_macos_cloudmensis
{
	meta:
		description = "Identify the CloudMensis/SNOWDRIFT malware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.21"
		reference = "https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/"
		sample = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
		DaysofYARA = "52/100"

	strings:
		$ = "SearchAndMoveFS:removable:"
		$ = "SavePetConfigData"
		$ = "csrutil status | grep disabled"
		$ = "CheckScreenSaverState"

	condition:
		all of them

}
private rule file_macho
{
	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
}

rule macho_ui_swiftui
{
	meta:
		description = "Identify *OS executable built w/ SwiftUI"
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.28"
		reference = "https://blog.timac.org/2022/0818-state-of-appkit-catalyst-swiftui-mac/"
		DaysofYARA = "28/100"

	strings:
		$framework = "/System/Library/Frameworks/SwiftUI.framework/Versions/A/SwiftUI"
		$symbol = "s7SwiftUI3AppPAAE4mainyyFZ"
	condition:
		file_macho and
		any of them
}

rule macho_ui_appkit
{
	meta:
		description = "Identify *OS executable built w/ AppKit"
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.28"
		reference = "https://blog.timac.org/2022/0818-state-of-appkit-catalyst-swiftui-mac/"
		DaysofYARA = "28/100"

	strings:
		$framework = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"
		$symbol = "NSApplicationMain"
	condition:
		file_macho and
		any of them
}

rule macho_ui_catalyst
{
	meta:
		description = "Identify *OS executable built w/ Mac Catalyst"
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.28"
		reference = "https://blog.timac.org/2022/0818-state-of-appkit-catalyst-swiftui-mac/"
		DaysofYARA = "28/100"

	strings:
		$framework = "/System/iOSSupport/System/Library/Frameworks/UIKit.framework/Versions/A/UIKit"
		$symbol = "NSApplicationMain"
	condition:
		file_macho and
		any of them
}

rule mal_cia_ransomware
{
	meta:
		description = "Identify macOS CIA ransomware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.29"
		sample = "1de673936636733112f29c8b8e15867ef1f288c5e5799615348f7a569c523de4"
		DaysofYARA = "29/100"

	strings:
		$log = "tagging file: %s"
		$name = "http://%s:8080/readme"
		$cia = "cia.gov was here"
		$background = "github.com/reujab/wallpaper.SetFromURL"
		$destop = "/Desktop2"
		$image = "http://%s:8080/imageinconsistent"

	condition:
		all of them
}

rule mal_ddosia_go_stresser_client
{
	meta:
		description = "Identify the ddosia/go_stresser client"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.27"
		sample = "7e1727e018a040920c4b4d573d2f4543733ed8e3f185a9596f8ba2c70029a2bb"
		DaysofYARA = "58/100"

	strings:
		$s1 = "client_id.txt"
		$s2 = "_go_stresser"
		$s3 = "\\$_\\d|\\$_\\d{2}"

	condition:
		all of them
}
rule mal_final_cut_pro
{
	meta:
		description = "Identify macOS Logic Pro X Cryptocurrency malware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.25"
		sample = "33114dd11009871fa6ad54797b45874d310eed2ad2f1da797f774701363be054"
		reference = "https://www.jamf.com/blog/cryptojacking-macos-malware-discovered-by-jamf-threat-labs/"
		DaysofYARA = "56/100"

	strings:
		$s1 = "Task %@ is not running"
		$s2 = "STPrivilegedTaskDidTerminateNotification"
		$s3 = "I2P" nocase
		$s4 = "FileExists"
		$s5 = "DirExists"
		$s6 = "Traktor"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		4 of them
}



rule mal_final_cut_pro_i2pd
{
	meta:
		description = "Identify macOS Logic Pro X Cryptocurrency malware's embedded I2P daemon"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.26"
		sample = "810bb73988dc47558b220047534d6dab9a55632c1defa40a761543ebaaa2f02c"
		reference = "https://www.jamf.com/blog/cryptojacking-macos-malware-discovered-by-jamf-threat-labs/"
		DaysofYARA = "57/100"

	strings:
		$s1 = "/Users/user/dev/i2pd/stage-x86_64/lib"
		$s2 = "i2p::"
		$s3 = "pidfile"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}
rule mal_macos_coinminer_xmrig
{
	meta:
		description = "Identify macOS CoinMiner malware."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.05"
		sample = "fabe0b41fb5bce6bda8812197ffd74571fc9e8a5a51767bcceef37458e809c5c"
		DaysofYARA = "64/100"

	strings:
		$s0 = "XMRig"
		$s1 = "cryptonight"
		$s3 = "user\": \"pshp"
		$s4 = "pass\": \"x"
		$s5 = "url\": \"127.0.0.1:"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}

rule mal_macos_cointicker
{
	meta:
		description = "Identify macOS CoinTicker malware methods"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.21"
		reference = "https://www.malwarebytes.com/blog/news/2018/10/mac-cryptocurrency-ticker-app-installs-backdoors"
		sample = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
		DaysofYARA = "21/100"

	strings:
		$s1 = "relounch"
		$s2 = "This is a test"
		$s3 = "Super long string here"

	condition:
		file_macho and
		any of them
}
rule mal_macos_crossrat_jar
{
  meta:
    description = "Identify macOS CrossRAT JAR bundle"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.18"
    reference = "https://objective-see.org/blog/blog_0x28.html"
    sample = "15af5bbf3c8d5e5db41fd7c3d722e8b247b40f2da747d5c334f7fd80b715a649"
    DaysofYARA = "77/100"

  strings:
    $client = "crossrat/client.class"

  condition:
    uint32be(0) == 0x0504B0304 and
    all of them
}

rule mal_macos_crossrat_client
{
  meta:
    description = "Identify macOS CrossRAT client class"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.18"
    reference = "https://objective-see.org/blog/blog_0x28.html"
    sample = "d7e2bb4babf56a84febb822e7c304159367ba61c97afa30aa1e8d93686c1c6f0"
    DaysofYARA = "77/100"

  strings:
    $jar   = "mediamgrs.jar"
    $name0 = "os.name"
    $name1 = "user.name"

  condition:
    uint32be(0) == 0xCAFEBABE and
    all of them
}
rule mal_macos_dacls
{
  meta:
    description = "Identify the macOS DACLs backdoor."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.07"
    sample = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"
    DaysofYARA = "97/100"

  strings:
    $s0 = "SCAN\t%s\t%d.%d.%d.%d\t%d\n"
    $s1 = "%Y-%m-%d %X"
    $s2 = "{\"result\":\"ok\"}"

    $f0 = "http_send_post"
    $f1 = "fetch_response"
    $f2 = "start_worm_scan"
    $f3 = "MakePacketHeader"

    $n0 = "mata_wc"
    $n1 = "Mata"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    (all of ($s*) or all of ($f*) or all of ($n*))
}
rule mal_macos_fkcodec {
  meta:
    description = "Identify macOS FKCodec backdoor."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.25"
    reference = "http://www.thesafemac.com/osxfkcodec-a-in-action/"
    sample = "979c6de81cc0f4e0a770f720ab82e8c727a2d422fe6179684b239fe0dc28d86c"
    DaysofYARA = "84/100"

  strings:
    $s0 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:29.0) Gecko/20100101 Firefox/29.0"
    $s1 = "/Users/yuriyfomenko/Develop/vova/projects/vidinstaller"
    $s2 = "safari_name=([^&?]*)"
    $s3 = "/tmp/download/ch.txt"
    $s4 = "/wait"
    $s5 = "/task"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    3 of them
}
rule mal_iwebservices
{
	meta:
		description = "Identify the iWebServices malware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.19"
		reference = "https://objective-see.org/blog/blog_0x72.html"
		sample = "3e66e664b05b695b0b018d3539412e6643d036c6d1000e03b399986252bddbfb"
		DaysofYARA = "50/100"

	strings:
		$s1 = "/update.php"
		$s2 = "/install.php"
		$s3 = "/tmp/iwup.tmp"

		$c1 = {
			e8 [4]         // call    _strchr
			49 89 c4       // mov     r12, rax
			45 31 ed       // xor     r13d, r13d  {0x0}
			4d 85 e4       // test    r12, r12
			74 ??          // je      0x1000018ab
			4c 89 e0       // mov     rax, r12
			49 ff c4       // inc     r12
			c6 00 00       // mov     byte [rax], 0x0
			be 3b 00 00 00 // mov     esi, 0x3b
			4c 89 e7       // mov     rdi, r12
			e8 [4]         // call    _strchr
			48 89 c3       // mov     rbx, rax
			45 31 ed       // xor     r13d, r13d  {0x0}
			48 85 db       // test    rbx, rbx
			74 ??          // je      0x1000018ab
			48 89 d8       // mov     rax, rbx
			48 ff c3       // inc     rbx
			c6 00 00       // mov     byte [rax], 0x0
			be 3b 00 00 00 // mov     esi, 0x3b
			48 89 df       // mov     rdi, rbx
			e8 [4]         // call    _strchr
			45 31 ed       // xor     r13d, r13d  {0x0}
			48 85 c0       // test    rax, rax
			74 ??          // je      0x10000188b
		}

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of ($s*) or
		all of ($c*)
}

rule mal_macos_loselose : OSXLoseLoseA
{
	meta:
		description = "Identify macOS LoseLose malware "
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.09"
		reference = "http://loselose.net"
		sample = "0e600ad7a40d1d935d85a47f1230a74e3ad4fd673177677827df9bca5bcb83e2"
		DaysofYARA = "68/100"

	strings:
		$s1 = "/Users/zachgage/Projects/"
		$s2 = "zach/virus/build/virus.build"
		$s3 = "ofxDirList - attempting to open %s"
		$s4 = "result in files on your hard drive"
		$s5 = "lose/lose"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		4 of them
}
rule mal_macos_macstealer {
  meta:
    description = "Identify macOS MacStealer malware."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.26"
    references = "https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware"
    sample = "1153fca0b395b3f219a6ec7ecfc33f522e7b8fc6676ecb1e40d1827f43ad22be"
    DaysofYARA = "85/100"

  strings:
    // config imports
    $s0 = "data.keychain"
    $s1 = "data.exdocusdecrypt"

    // support_file_extensions
    $s2 = { 74 78 74 [1-3] 75 2e 64 6f 63 [1-3] 75 2e 64 6f 63 78 [1-3] 75 2e 70 64 66 [1-3] 75 2e 78 6c 73 [1-3] 75 2e 78 6c 73 78 [1-3] 75 2e 70 70 74 [1-3] 75 2e 70 70 74 78 [1-3] 75 2e 6a 70 67 [1-3] 75 2e 70 6e 67 [1-3] 75 2e 62 6d 70 [1-3] 75 2e 6d 70 33 [1-3] 75 2e 7a 69 70 [1-3] 75 2e 72 61 72 [1-3] 75 2e 70 79 [1-3] 61 64 62 [1-3] 75 2e 63 73 76 [1-3] 75 2e 6a 70 65 67 }
    // support_folder_names
    $s3 = { 61 44 65 73 6b 74 6f 70 [1-3] 61 44 6f 63 75 6d 65 6e 74 73 [1-3] 61 44 6f 77 6e 6c 6f 61 64 73 [1-3] 61 4d 6f 76 69 65 73 [1-3] 61 4d 75 73 69 63 [1-3] 61 50 69 63 74 75 72 65 73 [1-3] 61 50 75 62 6c 69 63 }

    // bot id
    $s4 = "B8729059DDBF6359F136F699030BD4F5"

    // OSAScript
    $s5 = "osascript -e \\'display dialog \\\"{message}\\\" with title \\\"{title}\\\" with icon caution default answer \\\"\\\" with hidden answer"

    // keychain 
    $s6 = "security list-keychains"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    3 of them
}

rule mal_macos_netwire
{
	meta:
		description = "Identify the macOS Netwire Client"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.10"
		sample = "07a4e04ee8b4c8dc0f7507f56dc24db00537d4637afee43dbb9357d4d54f6ff4"
		DaysofYARA = "69/100"

	strings:
		$s0 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
		$s1 = "%PATH%"
		$s2 = "%HOME%"
		$s3 = "%USER%"

		$c0 = {
			e8 [4]         //      call    sub_9487
			83 c4 0c       //      add     esp, 0xc
			bf ff 00 00 00 //      mov     edi, 0xff
			ba f8 e? ?? ?? //      mov     edx, data_e2f8
			89 d9          //      mov     ecx, ebx {var_6014}
			57             //      push    edi {var_78b4}  {0xff}
			68 ?? ?? ?? ?? //      push    data_e2f8 {var_78b8}
			57             //      push    edi {var_78bc}  {0xff}
			e8 [4]         //      call    sub_9502
			83 c4 0c       //      add     esp, 0xc
			ba f8 e? ?? ?? //      mov     edx, data_e3f8
			89 d9          //      mov     ecx, ebx {var_6014}
			57             //      push    edi {var_78b4}  {0xff}
			68 ?? ?? ?? ?? //      push    data_e3f8 {var_78b8}
			57             //      push    edi {var_78bc}  {0xff}
			e8 [4]         //      call    sub_9502
			83 c4 0c       //      add     esp, 0xc
			bf 20 00 00 00 //      mov     edi, 0x20
			ba f8 e? ?? ?? //      mov     edx, data_e4f8
			89 d9          //      mov     ecx, ebx {var_6014}
			57             //      push    edi {var_78b4}  {0x20}
			68 ?? ?? ?? ?? //      push    data_e4f8 {var_78b8}
			57             //      push    edi {var_78bc}  {0x20}
			e8 [4]         //      call    sub_9502
			83 c4 0c       //      add     esp, 0xc
			ba 2a e? ?? ?? //      mov     edx, data_e52a
			89 d9          //      mov     ecx, ebx {var_6014}
			56             //      push    esi {var_78b4}  {0x10}
			68 ?? ?? ?? ?? //      push    data_e52a {var_78b8}
			56             //      push    esi {var_78bc}  {0x10}
			e8 [3] ??      //      call    sub_9502
		}

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		2 of them
}
rule mal_macos_pureland : stealer_0xfff
{
	meta:
		description = "Identify macOS PureLand crypto stealer."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.04"
		sample = "82633f6fec78560d657f6eda76d11a57c5747030847b3bc14766cec7d33d42be"
		DaysofYARA = "63/100"
		DaysofYARA = "67/100"

	strings:
		$s0 = "system_profiler SPHardwareDataType > /Users/"
		$s1 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}' > /Users/"
		$s2 = "/Library/Application Support/Exodus/exodus.wallet/" // Exodus Path
		$s3 = "/.dkdbsqtl/vakkdsr"                                 // Electrum Path

		$ext0 = "nkbihfbeogaeaoehlefnkodbefgpgknn" // MetaMask
		$ext1 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" // Phantom
		$ext2 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" // TronLink
		$ext3 = "efbglgofoippbgcjepnhiblaibcnclgk" // Martian

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		60% of them
}
rule mal_macos_rshell
{
	meta:
		description = "Identify macOS rshell backdoor."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.19"
		sample = "3a9e72b3810b320fa6826a1273732fee7a8e2b2e5c0fd95b8c36bbab970e830a"
		DaysofYARA = "78/100"

	strings:
		$s0 = "/proc/self/exe"
        $s1 = "/tmp/guid"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}
rule mal_macos_silver_sparrow_distribution {
  meta:
    description = "Identify macOS SilverSparrow pkg distrubtion scripts."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.23"
    references = "https://redcanary.com/blog/clipping-silver-sparrows-wings/"
    sample = "b60f1c6b95b8de397e7d92072412d1970ba474ff168ccabbc641d2a65b307b8a"
    DaysofYARA = "82/100"

  strings:
    $a0 = { 61 70 70 65 6E 64 4C 69 6E 65 (78 | 79) }
    $a1 = { 77 72 69 74 65 54 6F 46 69 6C 65 (78 | 79) }

    $b0 = "/usr/libexec/PlistBuddy -c 'Add :ProgramArguments:2 string \\\"~/Library/Application"
    $b1 = "${initAgentPath};"

  condition:
    any of ($a*) and all of ($b*)
}

rule mal_macos_silver_sparrow {
  meta:
    description = "Identify macOS SilverSparrow distrubtion scripts."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.24"
    references = "https://redcanary.com/blog/clipping-silver-sparrows-wings/"
    sample = "b60f1c6b95b8de397e7d92072412d1970ba474ff168ccabbc641d2a65b307b8a"
    DaysofYARA = "83/100"

  strings:
    $a0 = {
    48 bf 48 65 6c 6c 6f 2c 20 57  // mov     rdi, 'Hello, W'
    48 be 6f 72 6c 64 21 00 00 ed  // mov     rsi, 'orld!\x00\x00\xed'
    e8                             // call    _$s7SwiftUI18LocalizedStringKeyV13stringLiteralACSS_tcfC
    }
    $a1 = {
    48 bf 59 6f 75 20 64 69 64 20  // mov     rdi, 'You did '
    48 be 69 74 21 00 00 00 00 eb  // mov     rsi, 'it!\x00\x00\x00\x00\xeb'
    e8                             // call    _$s7SwiftUI18LocalizedStringKeyV13stringLiteralACSS_tcfC
    }

    $b0 = "SwiftUI6VStackVMn"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    any of ($a*) and all of ($b*)
}
rule mal_macos_smoothoperator {
  meta:
    description = "Identify macOS SmoothOperator first stage."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.30"
    references = "https://objective-see.org/blog/blog_0x73.html"
    sample = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
    DaysofYARA = "89/100"

  strings:
    $s0 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Safari/53" xor(0x01-0xff)
    $s1 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma" xor(0x01-0xff)
    $s2 = "%s/Library/Application Support/3CX Desktop App/%" xor(0x01-0xff)
    $s3 = "/System/Library/CoreServices/SystemVersion.plist" xor(0x01-0xff)

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    2 of them
}

rule mal_macos_smoothoperator_updateagent {
  meta:
    description = "Identify macOS SmoothOperator second stage."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.03"
    references = "https://objective-see.org/blog/blog_0x74.html"
    sample = "6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59"
    DaysofYARA = "93/100"

  strings:
    $s0 = "https://sbmsa.wiki/blog/_insert"
    $s1 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma=true" xor
    $s2 = "%s/Library/Application Support/3CX Desktop App/config.json" xor
    $s3 = "%s/Library/Application Support/3CX Desktop App/.main_storage" xor
    $s4 = "gzip, deflate" xor(0x01-0xff)
    $s5 = "User-Agent" xor(0x01-0xff)
    $s6 = "Connection" xor(0x01-0xff)

    $f0 = "parse_json_config"
    $f1 = "enc_text"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    2 of ($s*) or
    all of ($f*)
}

rule mal_macos_systemd
{
	meta:
		description = "Identify the macOS systemd (Demsty, ReverseWindow) backdoor."
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.02.28"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.systemd"
		sample = "6b379289033c4a17a0233e874003a843cd3c812403378af68ad4c16fe0d9b9c4"
		DaysofYARA = "59/100"

	strings:
		$s1 = "This file is corrupted and connot be opened\n"
		$s2 = "#!/bin/sh\n. /etc/rc.common\nStartService (){\n    ConsoleMessage \"Start system Service\"\n"
		$s3 = "}\nStopService (){\n    return 0\n}\nRestartService (){\n    return 0\n}\nRunService \"$1\"\n"
		$s4 = "StartupParameters.plist"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}
rule mal_macos_ventir_dropper: dropper {
  meta:
    description = "Identify macOS Ventir backdoor dropper."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.20"
    references = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample = "59539ff9af82c0e4e73809a954cf2776636774e6c42c281f3b0e5f1656e93679"
    DaysofYARA = "79/100"

  strings:
    $s0 = "/proc/self/exe"
    $s1 = "/bin/mv -f %s/updated.kext /System/Library/Extensions/updated.kext"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    all of them
}

rule mal_macos_ventir_keylog: keylogger {
  meta:
    description = "Identify macOS Ventir backdoor's keylogger component."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.21"
    references = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample = "92667ebbd1bc05e1abd6078d7496c26e50353122bc71b89135f2c71bcad18440"
    DaysofYARA = "80/100"

  strings:
    $s0     = "[command]"
    $s1     = "[option]"
    $s2     = "/Library/.local/.logfile"

    $keytab = { 61 73 64 66 68 67 7a 78 63 76 00 62 71 77 65 72 79 74 31 32 33 34 36 35 3d 39 37 2d 38 30 5d 6f 75 5b 69 70 0d 6c 6a 27 6b 3b 5c 2c 2f 6e 6d 2e 09 20 60 08 00 1b 00 00 00 00 00 00 00 00 00 00 00 2e 00 2a 00 2b 00 00 00 00 00 2f 0d 00 2d 00 00 00 30 31 32 33 34 35 36 37 38 39 }

    $fp     = "/proc/self/exe"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    all of ($s*) and $keytab and
    not $fp
}

rule mal_macos_ventir_watchdog {
  meta:
    description = "Identify macOS Ventir backdoor's watchdog component - reweb."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.21"
    references = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample = "14e763ed4e95bf13a5b5c4ce98edbe2bbbec0d776d66726dfe2dd8b1f3079cb1"
    DaysofYARA = "81/100"

  strings:
    $s0 = "/Users/maakira/"
    $s1 = "killall -9 update"
    $s2 = "reweb"

    $fp = "/proc/self/exe"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    all of ($s*) and
    not $fp
}


rule mal_macos_weaponx
{
	meta:
		description = "Identify the macOS WeaponX rootkit PoC."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.11"
		reference = "http://phrack.org/issues/66/16.html"
		sample = "5cf59f415ee67784227a2e9009ba9b3b3866d28d3d8f2b2c174368e1afc6ef96"
		DaysofYARA = "70/100"

	strings:
		$s0 = "r00t"
		$s1 = "com.nemo.kext.WeaponX"
		$s2 = "_antimain"
		$s3 = "_realmain"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		3 of them
}
rule mal_macos_xslcmd
{
	meta:
		description = "Identify macOS XslCmd malware."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.03"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.xslcmd"
		sample = "1db30d5b2bb24bcc4b68d647c6a2e96d984a13a28cc5f17596b3bfe316cca342"
		DaysofYARA = "62/100"

	strings:
		$s0 = "/.fontset/"
		$s1 = "pxupdate.ini"
		$s2 = "dump address: 0x%p, len 0x%x"
		$s3 = { 2f 74 6d 70 2f 6f 73 [3-4] 2e 6c 6f 67 }

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}
rule mal_orat
{
	meta:
		description = "Identify the unpacked orat backdoors"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.24"
		reference = "https://www.sentinelone.com/blog/from-the-front-lines-unsigned-macos-orat-malware-gambles-for-the-win/"
		sample = "0e4a71b465f69e7cc4fa88f0c28c4ae69936577e678db0696b215e8d26503f8f"
		DaysofYARA = "24/100"

	strings:
		$a1 = "/agent/info"
		$a2 = "/agent/ping"
		$a3 = "/agent/upload"
		$a4 = "/agent/download"

		$b2 = "JoinTime"
		$b3 = "[(%s)==(%s)]<===>[(%s)==(%s)]"

		$c1 = "RK_NET"
		$c2 = "RK_ADDR"
		$c3 = "RK_NET"



	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		30% of them
}


rule mal_rat_spark_macOS
{
	meta:
		description = "Identify the Spark RAT backdoor built for macOS"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.25"
		reference = "https://www.sentinelone.com/labs/dragonspark-attacks-evade-detection-with-sparkrat-and-golang-source-code-interpretation/"
		reference = "https://github.com/XZB-1248/Spark/"
		DaysofYARA = "25/100"

	strings:
		$mac1 = "SendAppleEventToSystemProcess"
		$mac2 = "CompatCGImageCreateCopyWithColorSpace"

		$b1 = "COMMON.BRIDGE_IN_USE"
		$b2 = "COMMON.DEVICE_NOT_EXIST"
		$b3 = "COMMON.DISCONNECTED"
		$b4 = "COMMON.INVALID_BRIDGE_ID"
		$b5 = "COMMON.INVALID_PARAMETER"
		$b6 = "COMMON.OPERATION_NOT_SUPPORTED"
		$b7 = "COMMON.RESPONSE_TIMEOUT"
		$b8 = "COMMON.UNKNOWN_ERROR"

		$c1 = "PING"
		$c2 = "OFFLINE"
		$c3 = "LOCK"
		$c4 = "LOGOFF"
		$c5 = "HIBERNATE"
		$c6 = "SUSPEND"
		$c7 = "RESTART"
		$c8 = "SHUTDOWN"
		$c9 = "SCREENSHOT"
		$c10 = "TERMINAL_INIT"
		$c11 = "TERMINAL_INPUT"
		$c12 = "TERMINAL_RESIZE"
		$c13 = "TERMINAL_PING"
		$c14 = "TERMINAL_KILL"
		$c15 = "FILES_LIST"
		$c16 = "FILES_FETCH"
		$c17 = "FILES_REMOVE"
		$c18 = "FILES_UPLOAD"
		$c19 = "FILE_UPLOAD_TEXT"
		$c20 = "PROCESSES_LIST"
		$c21 = "PROCESS_KILL"
		$c22 = "DESKTOP_INIT"
		$c23 = "DESKTOP_PING"
		$c24 = "DESKTOP_KILL"
		$c25 = "DESKTOP_SHOT"
		$c26 = "COMMAND_EXEC"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of ($mac*) and
		any of ($b*) and
		any of ($c*)
}
rule crypto_addr
{
	meta:
		description = "Identify cryptocurreny payment wallets"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.06"
		DaysofYARA = "6/100"

	strings:
		$btc_p2sh = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,39}\b/
		$btc_p2wpkh = /\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b/
		$monero = /\b4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}\b/
		$zcash = /\bzs[a-z0-9]{76}\b/
		$zcash_ua = /\bu1[a-z0-9]{211}\b/

	condition:
		any of them
}
rule program
{
	meta:
		description = "Identify programs string thing"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.16"
		DaysofYARA = "75/100"

	strings:
		$str = { 40 28 23 29 50 52 4F 47 52 41 4D 3A [0-20] 20 20 50 52 4F 4A 45 43 54 3A [0-20] 0A }

	condition:
		any of them
}
rule susp_encoded_ip
{
	meta:
		description = "Identify encoded IP addresses - a form of obfuscation"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.24"
		DaysofYARA = "55/100"

	strings:
		$hex = /https?:\/\/0x[0-9A-Fa-f]+/
		$oct = /https?:\/\/0\d{3}\.0\d{3}\.0\d{3}/

	condition:
		any of them
}

rule macho_bad_entitlements
{
	meta:
		description = "Identify security related entitlement strings in Mach-o files, only in the entitlement blob."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.06"
		reference = "https://developer.apple.com/documentation/security/hardened_runtime"
		DaysofYARA = "37/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 7? } private

		$s1 = "com.apple.security.cs.allow-unsigned-executable-memory"
		$s2 = "com.apple.security.cs.disable-library-validation"
		$s3 = "com.apple.security.cs.allow-jit"
		$s4 = "com.apple.security.automation.apple-events"
		$s5 = "com.apple.security.cs.allow-dyld-environment-variables"
		$s6 = "com.apple.security.cs.disable-executable-page-protection"
		$s7 = "com.apple.security.cs.debugger"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of ($cs_magic*) and

		for any i in (1 .. #cs_magic_entitlement) : (
			any of ($s*) in ((@cs_magic_entitlement[i] + 8) .. @cs_magic_entitlement[i] + 8 + uint32be(@cs_magic_entitlement[i] + 4))
		)
}
rule susp_macho_loader
{
	meta:
		description = "Identify Mach-O excutables like the ObjCShellcodeLoader"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.17"
		reference = "https://github.com/slyd0g/ObjCShellcodeLoader/tree/main"
		sample = "0ca96a9647a3506aeda50c9f6df3d173098b80c81937777af245da768867a4c9"
		DaysofYARA = "76/100"

	strings:
		$s1 = "mach_vm_write failed to write shellcode"
		$s2 = "_mach_vm_allocate"
		$s3 = "_mach_vm_protect"
		$s4 = "_mach_vm_write"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		3 of them
}

rule susp_macos_browser_stealer
{
	meta:
		description = "Identify macOS runables that target browser history/credentials."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.19"
		reference = "https://tylergaw.com/blog/building-osx-apps-with-js/"
		reference = "https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5"
		DaysofYARA = "19/100"

	strings:
		$safari1 = "/Library/Safari/History.db"
		$safari2 = "/Library/Cookies"
		$chrome = "/Library/Application Support/Google/Chrome/Default/History"
		$ffox = "/Library/Application Support/Firefox/Profiles/"

		$sec = "security find-generic-password"

	condition:
		any of (file_*) and
		any of them
}
rule susp_macos_elite_keylogger
{
	meta:
		description = "Identify macOS Elite Keylogger."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.06"
		sample = "edf5033a273bfbaebc721eb8dc30370bc0cd2b596d40051e19fdd32475d62194"
		DaysofYARA = "65/100"

	strings:
		$s0 = "Install_Elite_Keylogger"
		$s1 = { 45 6C 69 74 65 [0-1] 4B 65 79 6C 6F 67 67 65 72 }
		$s2 = "congratInvisible"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}
rule susp_macos_shellcode
{
	meta:
		description = "Identify macOS shellcode from @evilbit."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.15"
		reference = "https://github.com/theevilbit/shellcode/tree/master/osx/x64"
		DaysofYARA = "74/100"

	strings:
		$binsh = {
			48 31 f6                      // xor     rsi, rsi  {0x0}
			56                            // push    rsi {var_8}  {0x0}
			48 bf 2f 2f 62 69 6e 2f 73 68 // mov     rdi, 0x68732f6e69622f2f
			57                            // push    rdi {var_10}  {0x68732f6e69622f2f}
			48 89 e7                      // mov     rdi, rsp {var_10}
			48 31 d2                      // xor     rdx, rdx  {0x0}
			48 31 c0                      // xor     rax, rax  {0x0}
			b0 02                         // mov     al, 0x2
			48 c1 c8 28                   // ror     rax, 0x28  {0x2000000}
			b0 3b                         // mov     al, 0x3b
			0f 05                         // syscall
		}

		$bindsc = {
			48 31 ff                      //  xor     rdi, rdi  {sub_0}
			40 b7 02                      //  mov     dil, 0x2
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			40 b6 01                      //  mov     sil, 0x1
			48 31 d2                      //  xor     rdx, rdx  {sub_0}
			48 31 c0                      //  xor     rax, rax  {sub_0}
			b0 02                         //  mov     al, 0x2
			48 c1 c8 28                   //  ror     rax, 0x28  {0x2000000}
			b0 61                         //  mov     al, 0x61
			49 89 c4                      //  mov     r12, rax  {0x2000061}
			0f 05                         //  syscall
			49 89 c1                      //  mov     r9, rax
			48 89 c7                      //  mov     rdi, rax
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			56                            //  push    rsi {var_8}  {sub_0}
			be 01 02 11 5c                //  mov     esi, 0x5c110201
			83 ee 01                      //  sub     esi, 0x1  {0x5c110200}
			56                            //  push    rsi {var_10}  {0x5c110200}
			48 89 e6                      //  mov     rsi, rsp {var_10}
			b2 10                         //  mov     dl, 0x10
			41 80 c4 07                   //  add     r12b, 0x7
			4c 89 e0                      //  mov     rax, r12  {0x2000068}
			0f 05                         //  syscall
			48 31 f6                      //  xor     rsi, rsi
			48 ff c6                      //  inc     rsi  {0x1}
			41 80 c4 02                   //  add     r12b, 0x2
			4c 89 e0                      //  mov     rax, r12  {0x200006a}
			0f 05                         //  syscall
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			41 80 ec 4c                   //  sub     r12b, 0x4c
			4c 89 e0                      //  mov     rax, r12  {0x200001e}
			0f 05                         //  syscall
			48 89 c7                      //  mov     rdi, rax
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			41 80 c4 3c                   //  add     r12b, 0x3c
			4c 89 e0                      //  mov     rax, r12  {0x200005a}
			0f 05                         //  syscall
			48 ff c6                      //  inc     rsi
			4c 89 e0                      //  mov     rax, r12  {0x200005a}
			0f 05                         //  syscall
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			56                            //  push    rsi {var_18}  {sub_0}
			48 bf 2f 2f 62 69 6e 2f 73 68 //  mov     rdi, 0x68732f6e69622f2f
			57                            //  push    rdi {var_20}  {0x68732f6e69622f2f}
			48 89 e7                      //  mov     rdi, rsp {var_20}
			48 31 d2                      //  xor     rdx, rdx  {sub_0}
			41 80 ec 1f                   //  sub     r12b, 0x1f  {0x3b}
			4c 89 e0                      //  mov     rax, r12  {0x200003b}
			0f 05                         //  syscall
		}

	condition:
		any of them
}


rule susp_macos_sniperspy
{
	meta:
		description = "Identify the macOS SniperSpy backdoor."
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.02.12"
		reference = "https://www.flexispy.com/en/compatibility.htm?utm_source=sniperspy"
		sample = "529a659259e1a816d9192aab7b97d0281776ab8ef360d2c6c95e14a03ccda06a"
		DaysofYARA = "71/100"

	strings:
		$s1 = "/Shared/.syslogagent/syslogset.plist"
		$s2 = "syslogagent.app"
		$s3 = "sniperspy"


	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}
rule tool_network_free_code
{
	meta:
		description = "Identify executables with domains with free hosting of code."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.05"
		DaysofYARA = "5/100"

	strings:
		$cf_workers = ".workers.dev" xor
		$cf_pages = ".pages.dev" xor
		$vercel_app = ".vercel.app" xor
		$vercel_dev = ".vercel.dev" xor
		$vercel_now = ".now.sh" xor
		$deno = ".deno.dev" xor
		$fly = ".fly.dev" xor
		$deta = ".deta.dev" xor

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of them
}
rule lang_nim
{
	meta:
		description = "Identify a Nim binary regardless of format (PE, Macho, ELF) or arch."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.03"
		sample = "8ec44187e50c15a7c4c89af4a1e99c63c855539101ec1ef4588d2e12e05f7d2b" // NimGrabber
		DaysofYARA = "3/100"

	strings:
		$nim = "@nim"

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		#nim > 4
}

rule tool_nimplant
{
	meta:
		description = "Identify the Nimplan binary based off strings in their blog."
		author = "@shellcromancer <root@shellcromancer.io>"
		version = "0.1"
		date = "2023-01-03"
		reference = "https://casvancooten.com/posts/2021/08/building-a-c2-implant-in-nim-considerations-and-lessons-learned/#introducing-nimplant---a-lightweight-implant-and-c2-framework"
		DaysofYARA = "3/100"

	strings:
		$name = "nimplant" nocase

		$str0 = "Invalid number of arguments received. Usage: 'reg [query|add] [path] <optional: key> <optional: value>'"
		$str1 = "Invalid registry. Only 'HKCU' and 'HKLM' are supported"
		$str2 = "Unknown reg command. Please use 'reg query' or 'reg add' followed by the path (and value when adding a key)."
		$str3 = "Invalid number of arguments received. Usage: 'upload [local file] [optional: remote file]'."
		$str4 = "Something went wrong uploading the file (Nimplant did not receive response from staging server '"
	condition:
		lang_nim and
		(
			$name or
			3 of ($str*)
		)
}

rule wasm_coinminer
{
	meta:
		description = "Identify WebAssembly programs that perform cryptocurrency PoW operations."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.18"
		reference = "https://www.forcepoint.com/blog/x-labs/browser-mining-coinhive-and-webassembly"
		sample = "5117b6d9fd649e5946be0d3cbe4f285d14f64ca2"
		DaysofYARA = "18/100"
	strings:
		$s1 = "cryptonight"
		$s2 = "cryptonite"
		$s3 = "hashes per second"
		$s4 = "cn_slow_hash"

	condition:
		file_wasm and
		any of them
}