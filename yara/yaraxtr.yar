import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "macho"
import "math"
import "time"

import "pe"

rule SUSP_NET_Large_Static_Array_In_Small_File_Jan24 {
   meta:
      description = "Detects large static arrays in small .NET files "
      author = "Jonathan Peters"
      date = "2024-01-11"
      reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
      hash = "7d68bfaed20d4d7cf2516c2b110f460cf113f81872cd0cc531cbfa63a91caa36"
      score = 60
   strings:
      $op = { 5F 5F 53 74 61 74 69 63 41 72 72 61 79 49 6E 69 74 54 79 70 65 53 69 7A 65 3D [6-] 00 }
   condition:
      uint16(0) == 0x5a4d and
	  pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
	  filesize < 300KB and
	  #op == 1
}
import "pe"

rule DOTNET_SingleFileHost_Bundled_App {
	meta:
		description = "Detects single file host .NET bundled apps."
		author = "Jonathan Peters"
		date = "2024-01-02"
		reference = "https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file"
	strings:
		$ = "singlefilehost.exe" ascii
		$ = "singlefilehost.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		1 of them and
		pe.exports("DotNetRuntimeInfo") and
		pe.exports("CLRJitAttachState")
}
rule MAL_NET_LimeCrypter_RunPE_Jan24
{
	meta:
		description = "Detects LimeCrypter RunPE module. LimeCrypter is an open source .NET based crypter and loader commonly used by threat actors"
		author = "Jonathan Peters"
		date = "2024-01-16"
		reference = "https://github.com/NYAN-x-CAT/Lime-Crypter/tree/master"
		hash = "bcc8c679acfc3aabf22ebdb2349b1fabd351a89fd23a716d85154049d352dd12"
		score = 80
	strings:
		$op1 = { 1F 1A 58 1F 1A 58 28 }
		$op2 = { 20 B3 00 00 00 8D ?? 00 00 01 13 ?? 11 ?? 16 20 02 00 01 00 }
		$op3 = { 11 0? 11 0? 20 00 30 00 00 1F 40 28 ?? 00 00 06 }
		$op4 = { 6E 20 FF 7F 00 00 6A FE 02 }

		$s1 = "RawSecurityDescriptor" ascii
		$s2 = "CommonAce" ascii
	condition:
		uint16(0) == 0x5a4d and
		all of ($s*) and
		2 of ($op*)
}
rule MAL_NET_NixImports_Loader_Jan24 {
	meta:
		description = "Detects open-source NixImports .NET malware loader. A stealthy loader using dynamic import resolving to evade static detection"
		author = "Jonathan Peters"
		date = "2024-01-12"
		reference = "https://github.com/dr4k0nia/NixImports/tree/master"
		hash = "dd3f22871879b0bc4990c96d1de957848c7ed0714635bb036c73d8a989fb0b39"
		score = 80
	strings:
		$op1 = { 1F 0A 64 06 1F 11 62 60 } // Hash algorithm
		$op2 = { 03 20 4D 5A 90 00 94 4B 2A } // Magic
		$op3 = { 20 DE 7A 1F F3 20 F7 1B 18 BC } // Hardcoded function hashes
		$op4 = { 20 CE 1F BE 70 20 DF 1F 3E F8 14 } // Hardcoded function hashes

		$sa1 = "OffsetToStringData" ascii
		$sa2 = "GetRuntimeMethods" ascii
		$sa3 = "netstandard" ascii
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		2 of ($op*)
}
rule Eazfuscator_String_Encryption : suspicious
{
	meta:
		name = "Eazfuscator"
		category = "obfuscation"
		description = "Eazfuscator.NET string encryption"
		author = "Jonathan Peters"
		created = "2024-01-01"
		reliability = 90
		tlp = "TLP:white"
		sample = "3a9ee09ed965e3aee677043ba42c7fdbece0150ef9d1382c518b4b96bbd0e442"
	strings:
		$sa1 = "StackFrame" ascii
		$sa2 = "StackTrace" ascii
		$sa3 = "Enter" ascii
		$sa4 = "Exit" ascii

		$op1 = { 11 ?? 18 91 11 ?? 1? 91 1F 10 62 60 11 ?? 1? 91 1E 62 60 11 ?? 17 91 1F 18 62 60 }
		$op2 = { D1 28 ?? 00 00 0A 0? 1F 10 63 D1 }
		$op3 = { 1F 10 63 D1 28 [3] 0A }
		$op4 = { 7B ?? 00 00 04 16 91 02 7B ?? 00 00 04 17 91 1E 62 60 02 7B ?? 00 00 04 18 91 1F 10 62 60 02 7B ?? 00 00 04 19 91 1F 18 62 60 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		(
			2 of ($op*) or
			#op1 == 2
		)
}

rule Eazfuscator_Code_Virtualization : suspicious
{
	meta:
		name = "Eazfuscator"
		category = "obfuscation"
		description = "Eazfuscator.NET code virtualization"
		author = "Jonathan Peters"
		created = "2024-01-01"
		reliability = 90
		tlp = "TLP:white"
		sample = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii

		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A } // VM Stream Init
		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		2 of ($op*)
}

rule ConfuserEx_Naming_Pattern : suspicious
{
	meta:
		name = "ConfuserEx"
		category = "obfuscation"
		description = "ConfuserEx Renaming Pattern"
		author = "Jonathan Peters"
		created = "2024-01-03"
		reliability = 90
	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii 
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }

		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}
	condition:
		uint16(0) == 0x5a4d
		and 2 of ($s*)
		and #name_pattern > 5
}

rule ConfuserEx_Packer : suspicious
{
	meta:
		name = "ConfuserEx"
		category = "obfuscation"
		description = "ConfuserEx Packer"
		author = "Jonathan Peters"
		created = "2024-01-09"
		reliability = 90
	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii

		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A }
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($s*) and
		2 of ($op*)
}



rule Reactor_Indicators : suspicious
{
	meta:
		name = ".NET Reactor"
		category = "obfuscation"
		description = "Ezriz .NET Reactor obfuscator"
		author = "Jonathan Peters"
		created = "2024-01-09"
		reliability = 90
	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
	condition:
      uint16(0) == 0x5a4d
		and 2 of them
}
rule SUSP_OBF_NET_ConfuserEx_Name_Pattern_Jan24 {
	meta:
		description = "Detects Naming Pattern used by ConfuserEx. ConfuserEx is a widely used open source obfuscator often found in malware"
		author = "Jonathan Peters"
		date = "2024-01-03"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2f67f590cabb9c79257d27b578d8bf9d1a278afa96b205ad2b4704e7b9a87ca7"
		score = 60
	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii 
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }

		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}
	condition:
		uint16(0) == 0x5a4d
		and 2 of ($s*)
		and #name_pattern > 5
}

rule SUSP_OBF_NET_ConfuserEx_Packer_Jan24 {
	meta:
		description = "Detects binaries packed with ConfuserEx compression packer. This feature compresses and encrypts the actual image into a stub that unpacks and loads the original image on runtime."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2570bd4c3f564a61d6b3d589126e0940af27715e1e8d95de7863579fbe25f86f"
		score = 70
	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii

		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A}
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }
	condition:
		uint16(0) == 0x5a4d
		and all of ($s*)
		and 2 of ($op*)
}
rule SUSP_OBF_NET_Eazfuscator_String_Encryption_Jan24
{
	meta:
		description = "Detects .NET images obfuscated with Eazfuscator string encryption. Eazfuscator is a widely used commercial obfuscation solution used by both legitimate software and malware."
		author = "Jonathan Peters"
		date = "2024-01-01"
		reference = "https://www.gapotchenko.com/eazfuscator.net"
		hash = "3a9ee09ed965e3aee677043ba42c7fdbece0150ef9d1382c518b4b96bbd0e442"
		score = 60
	strings:
		$sa1 = "StackFrame" ascii
		$sa2 = "StackTrace" ascii
		$sa3 = "Enter" ascii
		$sa4 = "Exit" ascii

		$op1 = { 11 ?? 18 91 11 ?? 1? 91 1F 10 62 60 11 ?? 1? 91 1E 62 60 11 ?? 17 91 1F 18 62 60 }
		$op2 = { D1 28 ?? 00 00 0A 0? 1F 10 63 D1 }
		$op3 = { 1F 10 63 D1 28 [3] 0A }
		$op4 = { 7B ?? 00 00 04 16 91 02 7B ?? 00 00 04 17 91 1E 62 60 02 7B ?? 00 00 04 18 91 1F 10 62 60 02 7B ?? 00 00 04 19 91 1F 18 62 60 } // (int)this.\u0003[0] | ((int)this.\u0003[1] << 8) | ((int)this.\u0003[2] << 0x10) | ((int)this.\u0003[3] << 0x18);
	condition:
		uint16(0) == 0x5a4d 
		and all of ($sa*) 
		and (
			2 of ($op*) 
			or
			#op1 == 2
		)
}

rule SUSP_OBF_NET_Eazfuscator_Virtualization_Jan24
{
	meta:
		description = "Detects .NET images obfuscated with Eazfuscator virtualization protection. Eazfuscator is a widely used commercial obfuscation solution used by both legitimate software and malware."
		author = "Jonathan Peters"
		date = "2024-01-02"
		reference = "https://www.gapotchenko.com/eazfuscator.net"
		hash = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
		score = 60
	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii

		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A } // VM Stream Init
		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }
	condition:
		uint16(0) == 0x5a4d 
		and all of ($sa*)
		and 2 of ($op*)
}
import "pe"

rule SUSP_OBF_NET_Reactor_Native_Stub_Jan24 {
	meta:
		description = "Detects native packer stub for version 4.5-4.7 of .NET Reactor. A pirated copy of version 4.5 of this commercial obfuscation solution is used by various malware families like BlackBit, RedLine, AgentTesla etc."
		author = "Jonathan Peters"
		date = "2024-01-05"
		reference = "https://notes.netbytesec.com/2023/08/understand-ransomware-ttps-blackbit.html"
		hash = "6e8a7adf680bede7b8429a18815c232004057607fdfbf0f4b0fb1deba71c5df7"
		score = 70
	strings:
		$op = {C6 44 24 18 E0 C6 44 24 19 3B C6 44 24 1A 8D C6 44 24 1B 2A C6 44 24 1C A2 C6 44 24 1D 2A C6 44 24 1E 2A C6 44 24 1F 41 C6 44 24 20 D3 C6 44 24 21 20 C6 44 24 22 64 C6 44 24 23 06 C6 44 24 24 8A C6 44 24 25 F7 C6 44 24 26 3D C6 44 24 27 9D C6 44 24 28 D9 C6 44 24 29 EE C6 44 24 2A 15 C6 44 24 2B 68 C6 44 24 2C F4 C6 44 24 2D 76 C6 44 24 2E B9 C6 44 24 2F 34 C6 44 24 30 BF C6 44 24 31 1E C6 44 24 32 E7 C6 44 24 33 78 C6 44 24 34 98 C6 44 24 35 E9 C6 44 24 36 6F C6 44 24 37 B4}
	condition:
		for any i in (0..pe.number_of_resources-1) : (pe.resources[i].name_string == "_\x00_\x00")
		and $op
}

rule SUSP_OBF_NET_Reactor_Indicators_Jan24
{
	meta:
		description = "Detects indicators of .NET Reactors managed obfuscation. Reactor is a commercial obfuscation solution, pirated versions are often abused by threat actors."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://www.eziriz.com/dotnet_reactor.htm"
		hash = "be842a9de19cfbf42ea5a94e3143d58390a1abd1e72ebfec5deeb8107dddf038"
		score = 65
	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
	condition:
      uint16(0) == 0x5a4d
		and 2 of them
}
import "pe"

rule SingleFileHost_App_Bundle
{
	meta:
		name = "DotNet"
		category = "compiler"
		description = "DotNet singlefilehost app bundle"
		author = "Jonathan Peters"
		created = "2024-01-03"
		reliability = 90
	strings:
		$ = "singlefilehost.exe" ascii
		$ = "singlefilehost.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		1 of them and
		pe.exports("DotNetRuntimeInfo") and
		pe.exports("CLRJitAttachState")
}
rule SUSP_NET_Shellcode_Loader_Indicators_Jan24 {
   meta:
      description = "Detects indicators of shellcode loaders in .NET binaries"
      author = "Jonathan Peters"
      date = "2024-01-11"
      reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
      hash = "c48752a5b07b58596564f13301276dd5b700bd648a04af2e27d3f78512a06408"
      score = 65
   strings:
      $sa1 = "VirtualProtect" ascii
      $sa2 = "VirtualAlloc" ascii
      $sa3 = "WriteProcessMemory" ascii
      $sa4 = "CreateRemoteThread" ascii
      $sa5 = "CreateThread" ascii
      $sa6 = "WaitForSingleObject" ascii

      $x = "__StaticArrayInitTypeSize=" ascii
   condition:
      uint16(0) == 0x5a4d and
      3 of ($sa*) and
      #x == 1
}
rule SUSP_Direct_Syscall_Shellcode_Invocation_Jan24 {
	meta:
		description = "Detects direct syscall evasion technqiue using NtProtectVirtualMemory to invoke shellcode"
		author = "Jonathan Peters"
		date = "2024-01-14"
		reference = "https://unprotect.it/technique/evasion-using-direct-syscalls/"
		hash = "f7cd214e7460c539d6f8d02b6650098e3983862ff658b76ea02c33f5a45fc836"
		score = 65
	strings:
		$ = { B8 40 00 00 00 67 4C 8D 08 49 89 CA 48 C7 C0 50 00 00 00 0F 05 [4-8] 4C 8D 3D 02 00 00 00 FF E0 }
	condition:
		all of them and
		filesize < 2MB
}
rule SUSP_OBF_PyArmor_Jan24
{
	meta:
		description = "Detects PyArmor python code obfuscation. PyArmor is used by various threat actors like BatLoader"
		author = "Jonathan Peters"
		date = "2024-01-16"
		reference = "https://www.trendmicro.com/en_us/research/23/h/batloader-campaigns-use-pyarmor-pro-for-evasion.html"
		hash = "2727a418f31e8c0841f8c3e79455067798a1c11c2b83b5c74d2de4fb3476b654"
		score = 65
	strings:
		$ = "__pyarmor__" ascii
		$ = "pyarmor_runtime" ascii
		$ = "pyarmor(__" ascii
		$ = { 50 79 61 72 6D 6F 72 20 [5] 20 28 70 72 6F 29 }
		$ = { 5F 5F 61 72 6D 6F 72 5F ( 65 78 69 74 | 77 72 61 70 | 65 6E 74 65 72 ) 5F 5F }
	condition:
		2 of them
}

rule SUSP_RLO_Exe_Extension_Spoofing_Jan24 {
   meta:
      description = "Detects Right-To-Left (RLO) Unicode (U+202E) extension spoofing for .exe files"
      author = "Jonathan Peters"
      date = "2024-01-14"
      reference = "https://unprotect.it/technique/right-to-left-override-rlo-extension-spoofing/"
      hash = "cae0ab10f7c1afd7941aff767a9b59901270e3de4d44167e932dae0991515487"
      score = 70
   strings:
      $ = { E2 80 AE 76 73 63 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // csv
      $ = { E2 80 AE 66 64 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // pdf
      $ = { E2 80 AE 78 73 6C 78 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // xlsx
      $ = { E2 80 AE 78 63 6F 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // docx
      $ = { E2 80 AE 70 69 7A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // zip
      $ = { E2 80 AE 67 6E 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // png
      $ = { E2 80 AE 67 65 70 6A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // jpeg
      $ = { E2 80 AE 67 70 6A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // jpg
      $ = { E2 80 AE 6E 6C 73 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // sln

      $ = { E2 80 AE 74 78 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 64 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 78 74 70 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 74 64 6f ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 74 65 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 69 67 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 70 6d 62 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 66 69 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 67 76 73 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 34 70 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 69 76 61 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6f 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6d 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6c 66 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6b 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 33 70 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 61 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 61 61 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 61 6c 66 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 67 67 6f ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 61 6d 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 72 61 72 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 7a 37 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 7a 67 72 61 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6f 73 69 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6c 6d 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6c 6d 65 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6d 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 74 72 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6d 68 63 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 61 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6b 6e 6c ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 73 6c 78 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 6f 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6d 63 6f 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
   condition:
      1 of them
}
import "pe"

rule SUSP_VCRuntime_Sideloading_Indicators_Aug23 {
   meta:
      description = "Detects indicators of .NET based malware sideloading as VCRUNTIME140"
      author = "Jonathan Peters"
      date = "2023-08-30"
      hash = "b4bc73dfe9a781e2fee4978127cb9257bc2ffd67fc2df00375acf329d191ffd6"
      score = 75
   condition:
      (filename == "VCRUNTIME140.dll" or filename == "vcruntime140.dll")
      and pe.imports("mscoree.dll", "_CorDllMain")
}

rule SUSP_VCRuntime_Sideloading_Indicators_1_Aug23 {
   meta:
      description = "Detects indicators of malware sideloading as VCRUNTIME140"
      author = "Jonathan Peters"
      date = "2023-08-30"
      hash = "b4bc73dfe9a781e2fee4978127cb9257bc2ffd67fc2df00375acf329d191ffd6"
      score = 75
   strings:
      $x = "Wine builtin DLL" ascii
   condition:
      (filename == "VCRUNTIME140.dll" or filename == "vcruntime140.dll")
      and ( pe.number_of_signatures == 0
      or not pe.signatures[0].issuer contain "Microsoft Corporation" )
      and not $x
}

rule Obfuscar
{
    meta:
        author = "kevoreilly"
        description = "Obfuscar xor routime"
        // cape_type = "AgentTesla Payload"
        // https://github.com/obfuscar/obfuscar/blob/65e9ced171e0f2a92d2c64c479c3a1ec3624802a/Obfuscar/Obfuscator.cs#L1693
    strings:
        $decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PyinstallerWiper
{
    meta:
        description = "Detects indicators of the PyinstallerWiper malware variant that downloads files to system directories, corrupts user files, and disables recovery"
        author = "Emirhan Ucan"
        reference = "https://github.com/HydraDragonAntivirus/HydraDragonIOC/tree/main/PyinstallerWiper"
        hash = "3227a61794ae08b789eea4d1dcc190c67ce47ea94d78a41cba867b7aaeebe4a7"
        date = "2025-02-10"

    strings:
        // File paths created by the malware
        $sys_path     = "c:\\Windows\\System32\\drivers\\sjs.sys"
        $inf_path     = "c:\\Windows\\inf\\sjs.inf"
        // Download URL for the payload
        $download_url = "https://download1640.mediafire.com/0cg81k7i3oog0Vrbdvt4z8Dm6cr_cYgIEn6I2oJdtsv-N_wutfpSfI4z9KrH_cLItET4oZQ6fIi8Feybi8udAp58vKj2ivjUNebKCSktSQxdnFgodWEDHYVdGqVc8cLsiSZPCZPB8BWlqxdub01nZnvJSnWIoj1sxQMJ4FIB554fCPA/pk3gvqwu9nc3fs4/notepad.exe"
        // Registry and command-line strings used to disable system recovery and defenses
        $disable_defender = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\" /v DisableAntiSpyware"
        $vssadmin         = "vssadmin delete shadows /all /quiet"
        $reg_del          = "reg delete \"HKLM\\SOFTWARE\" /f"
        // UI strings that indicate malicious intent
        $greeting         = "Helo :-)"
        $final_msg        = "Count your days."
        // Taskkill commands for critical processes
        $tk_svchost       = "taskkill /f /im svchost.exe"
        $tk_csrss         = "taskkill /f /im csrss.exe"
        // Marker used after corrupting files
        $mlbo_ext         = ".mlbo"

    condition:
        2 of ($sys_path, $inf_path, $download_url, $disable_defender, $vssadmin, $reg_del, $greeting, $final_msg, $tk_svchost, $tk_csrss, $mlbo_ext)
}

import "pe"
rule Possible_Emotet_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed indicators Emotet DLL loaded into memory March 2022"
  strings:
      $htt1 = "MS Shell Dlg" wide
      $mzh = "This program cannot be run in DOS mode"
  condition:
      (pe.imphash() == "066d4e2c6288c042d958ddc93cfa07f1" or pe.imphash() == "	38617efee413c2d5919637769ddb6a9") and $htt1 and $mzh
}

rule HydraSeven_loader
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "New custom loader observed since September 2023"
        reference = "https://security5magics.blogspot.com/2023/10/interesting-customloader-observed-in.html" 
  strings:
      $mz = "MZ"
      $astring1 = "app.dll" ascii
      $wstring1 = "webView2" wide
      $wstring2 = /https?:\/\/.{1,35}\/main/ wide
      $d = "EmbeddedBrowserWebView.dll" wide
  condition:
    (($astring1 and $wstring1 and $wstring2) or ($d and $wstring2)) and $mz at 0 and filesize<1MB
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Infostealer_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $reggie = /[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\.dll/ wide
      $web = /https?:/ nocase wide
      $negate1 = "saitek" nocase wide
  condition:
      ($reggie and $web) and not $negate1
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Infostealer_PowerShell
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed powershell command strings"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = /\[.\..\]::run\(\)/ nocase
      $b = /\[.\..\]::run\(\)/ nocase wide
      $c = "[Reflection.Assembly]::Load("
      $d = /\[[a-zA-Z0-9\._]{25,45}\]::[a-zA-Z0-9\._]{10,25}\(\)/
  condition:
      ($a or $b) or ($c and $d)
}
rule Jupyter_Infostealer_DLL_October2021
{
  meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "https://squiblydoo.blog/2021/10/17/solarmarker-by-any-other-name/" 
  strings:
      $reggie = /[0-9a-fA-F]{32}\.dll/ wide
      $web = /https?:/ nocase wide
      $path = "appdata" nocase wide
      $rsa = "RSAKeyValue" wide
      $packer = "dzkabr"
      $ps = "System.IO.File" wide
  condition:
      ($reggie and $web and $path) and ($rsa or $packer or $ps)
}
import "pe"

rule Redline_Detection
{
   meta:
      author = "Lucas Acha (http://www.lukeacha.com)"
      description = "Observed with Redline Stealer injected DLL"
  strings:
      $htt1 = "System.Reflection.ReflectionContext" wide
      $htt7 = "System.Runtime.Remoting" ascii
      $htt8 = "AesCryptoServiceProvider" ascii
      $htt9 = "DownloadString" ascii
      $htt10 = "CheckRemoteDebuggerPresent" ascii
      $htt6 = "System.IO.Compression" ascii
      $mzh = "This program cannot be run in DOS mode"
      $neg = "rsEngine.Utilities.dll" wide
  condition:
      (pe.imphash() == "dae02f32a21e03ce65412f6e56942daa") and all of ($htt*) and $mzh and filesize > 500KB and not $neg
}
import "pe"
rule Multifamily_RAT_Detection
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Generic Detection for multiple RAT families, PUPs, Packers and suspicious executables"
  strings:
      $htt1 = "WScript.Shell" wide
      $htt2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
      $htt3 = "\\nuR\\noisreVtnerruC\\swodniW" wide
      $htt4 = "SecurityCenter2" wide
      $htt5 = ":ptth" wide
      $htt6 = ":sptth" wide
      $htt7 = "System.Reflection" ascii
      $htt8 = "ConfuserEx" ascii
      $htt9 = ".NET Framework 4 Client Profile" ascii
      $htt10 = "CreateEncryptor" ascii
      $mzh = "This program cannot be run in DOS mode"
  condition:
      (pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e" or pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744") and 3 of ($htt*) and $mzh
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Dropped_File
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = "solarmarker.dat" nocase wide
  condition:
      all of them
}
rule Possible_Solarmarker_Backdoor_Nov2023
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed strings in the latest obfuscated solarmarker backdoor dll."
        reference = "https://security5magics.blogspot.com/2023/10/new-solarmarker-variant-october-2023.html" 
  strings:
    $a = /\x00<Module>\x00[a-zA-Z0-9]{40}/ ascii
    $h1 = {54 68 72 65 61 64 00 53 6C 65 65 70}
    $h2 = {54 68 72 65 61 64 00 53 74 61 72 74}
    $b = /\x00Select\x00[a-zA-Z0-9_]{40}/ ascii
    $c = "GenerateIV" ascii
    $d = "$$method0x" ascii
  condition:
    $a and $b and $c and $d and ($h1 or $h2)
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
  
*/
rule solarmarker_March2022
{

  meta:
      author = "Lucas Acha (http://www.lukeacha.com)"
      description = "observed strings with malicious DLL loaded by Soalrmarker Malware during March 2022 campaign"
      reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $off1 = { 59 d1 8c ?? 00 00 }
      $hex2 = { 6c 58 11 07 6c 58 }
      $hex3 = { 6c 5a 58 11 5c }
      $hex4 = { 6c 59 11 ed 6c ?? }
      $hex5 = { 6c 58 fe 0c 2? 01 6c }
      $hex6 = { 6c 58 11 07 11 08 }
      $hex7 = { 6c 5a 58 11 0? 6c }
  condition:
     ($off1 in (0x17d0..0x1a20) and 2 of ($hex*) and $mz at 0)
}
rule Solarmarker_DLL_Jan2023
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed ASCII and Wide strings of obfuscated solarmarker dll"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $wstring1 = "A+Aa+A" wide
      $astring1 = "hkResult" ascii
      $astring2 = "mscorlib" ascii
      $astring3 = "System.Reflection" ascii
      $astring4 = "CreateDecryptor" ascii
      $astring5 = "ToBase64String" ascii
  condition:
     $mz at 0 and $wstring1 and 1 of ($astring*)
}
import "pe"
rule Solarmarker_Dropper
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Based on import hash and string observations with March 2022 solarmarker dropper"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $htt1 = "PowerShell"
	    $htt2 = "System.Collections.ObjectModel"
      $htt3 = "System.Management.Automation"
      $htt4 = ".NETFramework"
      $htt5 = "HashAlgorithm"
  condition:
      pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e" and 3 of ($htt*)
}
rule Solarmarker_Packer
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed possible packer in hexdump at specific offset ranges."
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $c = { 68 6b 65 79 00 70 61 63 6b 65 64 00 }
  condition:
      $c in (0x10000..0x30000) or $c in (0x50000..0x60000) or $c in (0x70000..0x90000)
}

rule Solarmarker_Packer_2
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "another version showing observed possible packer in hexdump at specific offset ranges."
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $off1 = { 68 6b 65 79 00 46 72 6f 6d 42 61 73 65 36 34} 
      $off2 = { 70 61 63 6b 65 64 }
  condition:
     $off1 in (0x26000..0x32000) and $off2 in (0x26000..0x32000) and $mz at 0
}
rule Solarmarker_Packer_Strings
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed ASCII and Wide strings of obfuscated solarmarker dll"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $wstring1 = "zkabsr" wide
      $astring1 = "keyPath" ascii
      $astring2 = "hSection" ascii
      $astring3 = "valueName" ascii
      $astring4 = "StaticArrayInitTypeSize" ascii
      $astring5 = "KeyValuePair" ascii
  condition:
     $mz at 0 and $wstring1 and 1 of ($astring*)
}

rule Solarmarker_Packer_May_2023
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "another version showing observed possible packer in hexdump at specific offset ranges."
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $off1 = { 41 1? ?? 00 ?? 00 61 1? ?? 00 }
      $off2 = { 41 0? 23 00 ?? 00 61 0? 23 00 }
      $astring1 = "IDisposable" ascii
      $wstring1 = "0.0.0.0" wide
  condition:
     ($off1 in (0x80000..0x9FFFF) or $off2 in (0x72000..0x9FFFF)) and $astring1 and $wstring1 and $mz at 0 and filesize<1MB
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Suspicious_PS_Strings
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed set of strings which are likely malicious, observed with Jupyter malware. "
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
    strings:
        $a = "windowstyle=7" nocase
        $b = "[system.io.file]:" nocase
        $c = ":readallbytes" nocase
        $d = "system.text.encoding]::" nocase
        $e = "utf8.getstring" nocase
        $f = "([system.convert]::" nocase
        $g = "frombase64string" nocase
        $h = "[system.reflection.assembly]::load" nocase
        $i = "-bxor" nocase
    condition:
        6 of them
}
import "pe"
rule suspicious_obfuscated_script_detection
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed strings with suspicious AutoIT scripts"
  strings:
      $a = "NoTrayIcon" ascii
      $b = "Global" ascii
      $c = "StringTrimLeft" ascii
      $d = "StringTrimRight" ascii
      $e = "StringReverse" ascii
  condition:
      all of them and filesize < 3MB
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule vbs_downloader_jan2021
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "VBS downloader campaign appearing January 2021"
	referencs = "http://security5magics.blogspot.com/2021/01/new-vbs-downloader-variant-observed.html"
  strings:
      $a = "vbSystemModal" nocase
      $b = "programdata" nocase
      $c = "regsvr32" nocase
      $d = "objStream.Open" nocase
      $e = "responseBody" nocase
      $f = "a.setOption 2,13056" nocase
  condition:
      ($a and $b and $c and $d and $e) or $f
}
/*
    Suspicious Powershell in weaponized word documents
    Reference: 5c6148619abb10bb3789dcfb32f759a6
*/
rule suspicious_powershell_winword
{
    strings:
        $a = {D0 CF 11 E0 A1 B1 1A E1 00 00 00 00 00}
        $b = {4D 69 63 72 6F 73 6F 66 74 20 4F 66 66 69 63 65 20 57 6F 72 64 00}
        $c = "powershell -e" nocase
    condition:
        all of them
}
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule possible_wwlib_hijacking
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed with campaigns such as APT32, this attempts to look for the archive files such as RAR."
        reference = "040abac56542a2e0f384adf37c8f95b2b6e6ce3a0ff969e3c1d572e6b4053ff3" 
    strings:
        $a = "/wwlib.dll"
        $neg1 = "This program cannot be run in DOS mode"
        $neg2 = "Doctor Web"
        $neg3 = "pandasecurity.com"
    condition:
        $a and not any of ($neg1,$neg2,$neg3)
}

rule HackTool_Python_Pyramid_Generic {
    meta:
        description = "Detects generic Pyramid-based Python hacktools using in-memory execution and encryption techniques"
        author = "Emirhan Ucan"
        date = "2024-01-14"
        version = "0.1"
        category = "malware/hacktool"
        reference = "https://www.reddit.com/r/computerviruses/comments/1i0wf7w/fake_youtube_parnership/"
        reference2 = "https://www.virusview.net/malware/HackTool/Python/Pyramid"
        hash_description = "Hashes of known Pyramid tool samples"
        hash1 = "a08b0637632f4eb6de1512bb44f9ba787aaab2e92b0fb1f707ac6b8c0a366ccf"
        hash2 = "33f404d7d5feed8819b0981e7315ac7b213edfaaaf6d1ecd185c23ef5d77ccc9"
    strings:
        $in_memory_exec = /exec\(.*\.decode\(.*utf-8.*\)\)/ nocase  // In-memory execution
        $chacha20_func = /def\s+yield_chacha20_xor_stream/ nocase  // ChaCha20 encryption function
        $encryption_wrapper = /def\s+encrypt_wrapper\(.*encryption.*\)/ nocase  // Encryption wrapper function
        $ssl_bypass = /ssl\.CERT_NONE/ nocase  // SSL certificate verification bypass
        $base64_encode = /base64\.b64encode\(.*\)/ nocase  // Base64 encoding for obfuscation
        $dynamic_import = /class\s+CFinder.*moduleRepo.*_meta_cache.*sys\.meta_path/ nocase  // Dynamic Python module import
        $pyramid_reference = /AUTO-GENERATED PYRAMID CONFIG/ nocase  // Pyramid-specific configuration
    condition:
        all of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass, $dynamic_import) or 
        ($pyramid_reference and $base64_encode and 3 of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass))
}

private rule file_pe_header {
    meta:
        description = "Finds PE file MZ header as uint16"
        last_modified = "2024-01-01"
        author = "@petermstewart"
        DaysofYara = "1/100"

    condition:
        uint16(0) == 0x5a4d
}

private rule file_elf_header {
    meta:
        description = "Matches ELF file \x7fELF header as uint32"
        last_modified = "2024-01-02"
        author = "@petermstewart"
        DaysofYara = "2/100"

    condition:
        uint32(0) == 0x464c457f
}

private rule file_macho_header {
    meta:
        description = "Matches Mach-O file headers as uint32"
        last_modified = "2024-01-03"
        author = "@petermstewart"
        DaysofYara = "3/100"

    condition:
        uint32(0) == 0xfeedface or  //MH_MAGIC
        uint32(0) == 0xcefaedfe or  //MH_CIGAM
        uint32(0) == 0xfeedfacf or  //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or  //MH_CIGAM_64
        uint32(0) == 0xcafebabe or  //FAT_MAGIC
        uint32(0) == 0xbebafeca     //FAT_CIGAM
}

private rule file_pe_signed {
    meta:
        description = "Finds signed Windows executables"
        last_modified = "2024-01-04"
        author = "@petermstewart"
        DaysofYara = "4/100"
        
    condition:
        uint16(0) == 0x5a4d and
        pe.number_of_signatures >= 1
}

private rule file_zip {
    meta:
        description = "Finds files that look like ZIP archives"
        last_modified = "2024-02-12"
        author = "@petermstewart"
        DaysofYara = "43/100"
        ref = "https://en.wikipedia.org/wiki/ZIP_(file_format)"

    strings:
        $local_file_header = { 50 4b 03 04 }
        $central_directory_header = { 50 4b 01 02 }
        $end_of_central_directory = { 50 4b 05 06 }
        
    condition:
        $local_file_header at 0 and
        $central_directory_header and
        $end_of_central_directory
}

private rule file_zip_password_protected {
    meta:
        description = "Finds files that look like password-protected ZIP archives"
        last_modified = "2024-02-13"
        author = "@petermstewart"
        DaysofYara = "44/100"
        ref = "https://en.wikipedia.org/wiki/ZIP_(file_format)"
        ref = "https://twitter.com/tylabs/status/1366728540683599878"
        
    condition:
        file_zip and
        uint16(6) & 0x1 == 0x1 //Check the general purpose bit flag in the local file header
}

private rule file_msi {
    meta:
        description = "Finds Microsoft Installer (.msi) files"
        last_modified = "2024-03-02"
        author = "@petermstewart"
        DaysofYara = "62/100"

    strings:
        $magic = { d0 cf 11 e0 a1 b1 1a e1 }
        $clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        
    condition:
        $magic at 0 and
        $clsid
}

private rule file_pdf_header {
    meta:
        description = "Finds Portable Document Format (.pdf) files"
        last_modified = "2024-03-06"
        author = "@petermstewart"
        DaysofYara = "66/100"
        ref = "https://en.wikipedia.org/wiki/PDF"

    condition:
        uint32(0) == 0x46445025
}

/*
These rules utilise regular expressions to match cryptocurrency wallet addresses and may cause performance issues.
Comment them out if this is a problem for you.
*/
rule TTP_contains_BTC_address {
    meta:
        description = "Matches regex for Bitcoin wallet addresses."
        last_modified = "2024-01-08"
        author = "@petermstewart"
        DaysofYara = "8/100"

    strings:
        $r1 = /(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword ascii wide

    condition:
        filesize < 5MB and
        $r1
}

rule TTP_contains_ETH_address {
    meta:
        description = "Matches regex for Ethereum wallet addresses."
        last_modified = "2024-01-09"
        author = "@petermstewart"
        DaysofYara = "9/100"

    strings:
        $r1 = /0x[a-fA-F0-9]{40}/ fullword ascii wide

    condition:
        filesize < 5MB and
        $r1
}

rule TTP_contains_XMR_address {
    meta:
        description = "Matches regex for Monero wallet addresses."
        last_modified = "2024-01-10"
        author = "@petermstewart"
        DaysofYara = "10/100"

    strings:
        $r1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ fullword ascii wide

    condition:
        filesize < 5MB and
        $r1
}

rule TTP_WIP19_bad_cert {
    meta:
        description = "Matches known bad signing certificate serial number used by China-nexus threat actor WIP19."
        last_modified = "2024-01-05"
        author = "@petermstewart"
        DaysofYara = "5/100"
        ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
        sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"
        sha256 = "2f2f165ee5b81a101ebda0b161f43b54bc55afd8e4702c9b8056a175a1e7b0e0"
        
    condition:
        file_pe_signed and
        for any sig in pe.signatures:
        (
            sig.serial == "02:10:36:b9:e8:0d:16:ea:7f:8c:f0:e9:06:2b:34:55"
        )
}

rule MAL_SQLMaggie_strings {
    meta:
        description = "Matches strings found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
        last_modified = "2024-01-06"
        author = "@petermstewart"
        DaysofYara = "6/100"
        ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
        sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"
    
    strings:
        $a1 = "Account Owner Not Found For The SID"
        $a2 = "%s Isn't Successfully Hooked Yet"
        $a3 = "About To Execute: %s %s %s"
        $a4 = "RunAs User Password Command"
        $a5 = "Wait 5 To 10 Seconds For TS Taking Effect"
        $a6 = "Re-Install TS Successfullly"
        $a7 = "ImpersonateLoggedOnUser = %d"
        $a8 = "The Account %s Has Been Cloned To %s"
        $a9 = "Fileaccess ObjectName [TrusteeName] [Permission] Options"
        $a10 = "SQL Scan Already Running"
        $a11 = "HellFire2050"

    condition:
        file_pe_header and
        8 of them
}

rule MAL_SQLMaggie_dll_export {
    meta:
        description = "Matches DLL export found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
        last_modified = "2024-01-07"
        author = "@petermstewart"
        DaysofYara = "7/100"
        ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
        sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"

    condition:
        file_pe_header and
        pe.number_of_exports == 1 and
        pe.export_details[0].name == "maggie"
}

rule TTP_contains_onion_address {
    meta:
        description = "Matches regex for .onion addresses associated with Tor Hidden Services."
        last_modified = "2024-01-11"
        author = "@petermstewart"
        DaysofYara = "11/100"

    strings:
        $r1 = /[a-z2-7]{16}\.onion/ fullword ascii wide
        $r2 = /[a-z2-7]{55}d\.onion/ fullword ascii wide

    condition:
        filesize < 5MB and
        any of them
}

rule MAL_Akira_strings {
    meta:
        description = "Matches strings found in Akira ransomware sample."
        last_modified = "2024-01-12"
        author = "@petermstewart"
        DaysofYara = "12/100"
        sha256 = "3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c"

    strings:
        $a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
        $a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
        $b = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
        $c1 = "This is local disk:" wide
        $c2 = "This is network disk:" wide
        $c3 = "This is network path:" wide
        $c4 = "Not allowed disk:" wide

    condition:
        filesize < 2MB and
        file_pe_header and
        1 of ($a*) and
        $b and
        2 of ($c*)
}

rule MAL_Akira_ransomnote {
    meta:
        description = "Matches strings found in Akira ransom note sample."
        last_modified = "2024-01-13"
        author = "@petermstewart"
        DaysofYara = "13/100"

    strings:
        $a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
        $a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
        $b1 = "Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead"
        $b2 = "all your backups - virtual, physical - everything that we managed to reach - are completely removed"
        $b3 = "Moreover, we have taken a great amount of your corporate data prior to encryption"
        $b4 = "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue"
        $b5 = "We're fully aware of what damage we caused by locking your internal sources"
        $b6 = "At the moment, you have to know"
        $b7 = "Dealing with us you will save A LOT due to we are not interested in ruining your financially"
        $b8 = "We will study in depth your finance, bank & income statements, your savings, investments etc. and present our reasonable demand to you"
        $b9 = "If you have an active cyber insurance, let us know and we will guide you how to properly use it"
        $b10 = "Also, dragging out the negotiation process will lead to failing of a deal"
        $b11 = "Paying us you save your TIME, MONEY, EFFORTS and be back on track within 24 hours approximately"
        $b12 = "Our decryptor works properly on any files or systems, so you will be able to check it by requesting a test decryption service from the beginning of our conversation"
        $b13 = "If you decide to recover on your own, keep in mind that you can permanently lose access to some files or accidently corrupt them - in this case we won't be able to help"
        $b14 = "The security report or the exclusive first-hand information that you will receive upon reaching an agreement is of a great value"
        $b15 = "since NO full audit of your network will show you the vulnerabilities that we've managed to detect and used in order to get into, identify backup solutions and upload your data"
        $b16 = "As for your data, if we fail to agree, we will try to sell personal information/trade secrets/databases/source codes"
        $b17 = "generally speaking, everything that has a value on the darkmarket - to multiple threat actors at ones"
        $b18 = "Then all of this will be published in our blog"
        $b19 = "We're more than negotiable and will definitely find the way to settle this quickly and reach an agreement which will satisfy both of us"
        $b20 = "If you're indeed interested in our assistance and the services we provide you can reach out to us following simple instructions"
        $b21 = "Install TOR Browser to get access to our chat room"
        $b22 = "Keep in mind that the faster you will get in touch, the less damage we cause"

    condition:
        filesize < 100KB and
        1 of ($a*) and
        18 of ($b*)
}

rule MAL_BlackCat_Win_strings {
    meta:
        description = "Matches strings found in BlackCat ransomware Windows samples operated by ALPHV."
        last_modified = "2024-01-14"
        author = "@petermstewart"
        DaysofYara = "14/100"
        sha256 = "2587001d6599f0ec03534ea823aab0febb75e83f657fadc3a662338cc08646b0"
        sha256 = "c3e5d4e62ae4eca2bfca22f8f3c8cbec12757f78107e91e85404611548e06e40"

    strings:
        $a = "bcdedit /set {default}bcdedit /set {default} recoveryenabled"
        $b = "vssadmin.exe Delete Shadows /all /quietshadow_copy::remove_all_vss="
        $c = "wmic.exe Shadowcopy Deleteshadow_copy::remove_all_wmic="
        $d = "deploy_note_and_image_for_all_users="
        $e = "Control Panel\\DesktopWallpaperStyleWallPaperC:\\\\Desktop\\.png"
        $f = "Speed:  Mb/s, Data: Mb/Mb, Files processed: /, Files scanned:"

    condition:
        filesize > 2MB and filesize < 4MB and
        file_pe_header and
        all of them
}

rule MAL_BlackCat_Lin_strings {
    meta:
        description = "Matches strings found in BlackCat ransomware Linux samples operated by ALPHV"
        last_modified = "2024-01-15"
        author = "@petermstewart"
        DaysofYara = "15/100"
        sha256 = "3a08e3bfec2db5dbece359ac9662e65361a8625a0122e68b56cd5ef3aedf8ce1"
        sha256 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"

    strings:
        $a1 = "encrypt_app::linux"
        $a2 = "src/bin/encrypt_app/linux.rs"
        $a3 = "locker::core::os::linux::command"
        $b1 = "note_file_name"
        $b2 = "note_full_text"
        $b3 = "note_short_text"
        $b4 = "default_file_cipher"
        $b5 = "default_file_mode"
        $b6 = "enable_esxi_vm_kill"
        $b7 = "enable_esxi_vm_snapshot_kill"

    condition:
        filesize > 1MB and filesize < 3MB and
        file_elf_header and
        2 of ($a*) and
        5 of ($b*)
}

rule MAL_BlackCat_ransomnote {
    meta:
        description = "Matches strings found in two versions of ransom notes dropped by BlackCat (ALPHV)."
        last_modified = "2024-01-16"
        author = "@petermstewart"
        DaysofYara = "16/100"

    strings:
        $heading1a = ">> What happened?"
        $heading1b = ">> Introduction"
        $heading2 = ">> Sensitive Data"
        $heading3 = ">> CAUTION"
        $heading4a = ">> What should I do next?"
        $heading4b = ">> Recovery procedure"
        $a1 = "In order to recover your files you need to follow instructions below."
        $a2 = "clients data, bills, budgets, annual reports, bank statements"
        $a3 = "1) Download and install Tor Browser from: https://torproject.org/"
        $a4 = "2) Navigate to: http://"

    condition:
        filesize < 5KB and
        ($heading1a and $heading4a) or ($heading1b and $heading4b) and
        $heading2 and $heading3 and 
        all of ($a*)
}

rule MAL_Lockbit_2_Win_strings {
    meta:
        description = "Matches strings found in Lockbit 2.0 ransomware Windows samples."
        last_modified = "2024-01-17"
        author = "@petermstewart"
        DaysofYara = "17/100"
        sha256 = "36446a57a54aba2517efca37eedd77c89dfc06e056369eac32397e8679660ff7"
        sha256 = "9feed0c7fa8c1d32390e1c168051267df61f11b048ec62aa5b8e66f60e8083af"

    strings:
        $a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide
        $b1 = "All your files stolen and encrypted" wide
        $b2 = "for more information see" wide
        $b3 = "RESTORE-MY-FILES.TXT" wide
        $b4 = "that is located in every encrypted folder." wide
        $b5 = "You can communicate with us through the Tox messenger" wide
        $b6 = "If you want to contact us, use ToxID" wide

    condition:
        filesize > 800KB and filesize < 10MB and
        file_pe_header and
        $a and
        4 of ($b*)
}

rule MAL_Lockbit_2_macOS_strings {
    meta:
        description = "Matches strings found in Lockbit ransomware macOS sample."
        last_modified = "2024-01-18"
        author = "@petermstewart"
        DaysofYara = "18/100"
        sha256 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"

    strings:
        $a1 = "lockbit"
        $a2 = "restore-my-files.txt"
        $a3 = "_I_need_to_bypass_this_"
        $a4 = "kLibsodiumDRG"
        $b = "_Restore_My_Files_"

    condition:
        filesize < 500KB and
        file_macho_header and
        #b > 4 and
        all of ($a*)
}

rule MAL_Lockbit_2_ransomnote {
    meta:
        description = "Matches strings found in Lockbit 2.0 ransom note samples."
        last_modified = "2024-01-19"
        author = "@petermstewart"
        DaysofYara = "19/100"

    strings:
        $a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion"
        $b1 = "https://bigblog.at"
        $b2 = "http://lockbitsup4yezcd5enk5unncx3zcy7kw6wllyqmiyhvanjj352jayid.onion"
        $b3 = "http://lockbitsap2oaqhcun3syvbqt6n5nzt7fqosc6jdlmsfleu3ka4k2did.onion"
        $c1 = "LockBit 2.0 Ransomware"
        $c2 = "Your data are stolen and encrypted"
        $c3 = "The data will be published on TOR website"
        $c4 = "if you do not pay the ransom"
        $c5 = "You can contact us and decrypt on file for free on these TOR sites"
        $c6 = "Decryption ID:"

    condition:
        filesize < 5KB and
        $a and
        2 of ($b*) and
        5 of ($c*)
}

rule MAL_Royal_strings {
    meta:
        description = "Matches strings found in Windows and Linux samples of Royal ransomware."
        last_modified = "2024-01-20"
        author = "@petermstewart"
        DaysofYara = "20/100"
        sha256 = "312f34ee8c7b2199a3e78b4a52bd87700cc8f3aa01aa641e5d899501cb720775"
        sha256 = "9db958bc5b4a21340ceeeb8c36873aa6bd02a460e688de56ccbba945384b1926"
        sha256 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"

    strings:
        $a = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion"
        $b1 = "If you are reading this, it means that your system were hit by Royal ransomware"
        $b2 = "Please contact us via :"
        $b3 = "In the meantime, let us explain this case"
        $b4 = "It may seem complicated, but it is not!"
        $b5 = "Most likely what happened was that you decided to save some money on your security infrastructure"
        $b6 = "Alas, as a result your critical data was not only encrypted but also copied from your systems on a secure server"
        $b7 = "From there it can be published online"
        $b8 = "Then anyone on the internet from darknet criminals, ACLU journalists, Chinese government"
        $b9 = "and even your employees will be able to see your internal documentation: personal data, HR reviews, internal lawsuitsand complains, financial reports, accounting, intellectual property, and more"
        $b10 = "Fortunately we got you covered!"
        $b11 = "Royal offers you a unique deal.For a modest royalty(got it; got it ? )"
        $b12 = "Try Royal today and enter the new era of data security"
        $b13 = "We are looking to hearing from you soon"

    condition:
        filesize > 2000KB and filesize < 3500KB and
        (file_pe_header or file_elf_header) and
        $a and
        10 of ($b*)
}

rule HUNT_Royal_RSA_Public_Key {
    meta:
        description = "Matches an RSA Public Key block found in Royal ransomware Linux samples."
        last_modified = "2024-01-20"
        author = "@petermstewart"
        DaysofYara = "20/100"
        sha256 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"
        sha256 = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"

    strings:
        $key1 = "-----BEGIN RSA PUBLIC KEY-----"
        $key2 = "MIICCAKCAgEAp/24TNvKoZ9rzwMaH9kVGq4x1j+L/tgWH5ncB1TQA6eT5NDtgsQH"
        $key3 = "jv+6N3IY8P4SPSnG5QUBp9uYm3berObDuLURZ4wGW+HEKY+jNht5JD4aE+SS2Gjl"
        $key4 = "+lht2N+S8lRDAjcYXJZaCePN4pHDWQ65cVHnonyo5FfjKkQpDlzbAZ8/wBY+5gE4"
        $key5 = "Tex2Fdh7pvs7ek8+cnzkSi19xC0plj4zoMZBwFQST9iLK7KbRTKnaF1ZAHnDKaTQ"
        $key6 = "uCkJkcdhpQnaDyuUojb2k+gD3n+k/oN33Il9hfO4s67gyiIBH03qG3CYBJ0XfEWU"
        $key7 = "cvvahe+nZ3D0ffV/7LN6FO588RBlI2ZH+pMsyUWobI3TdjkdoHvMgJItrqrCK7BZ"
        $key8 = "TIKcZ0Rub+RQJsNowXbC+CbgDl38nESpKimPztcd6rzY32Jo7IcvAqPSckRuaghB"
        $key9 = "rkci/d377b6IT+vOWpNciS87dUQ0lUOmtsI2LLSkwyxauG5Y1W/MDUYZEuhHYlZM"
        $key10 = "cKqlSLmu8OTitL6bYOEQSy31PtCg2BOtlSu0NzW4pEXvg2hQyuSEbeWEGkrJrjTK"
        $key11 = "v9K7eu+eT5/arOy/onM56fFZSXfVseuC48R9TWktgCpPMkszLmwY14rp1ds6S7OO"
        $key12 = "/HLRayEWjwa0eR0r/GhEHX80C8IU54ksEuf3uHbpq8jFnN1A+U239q0CAQM="
        $key13 = "-----END RSA PUBLIC KEY-----"

    condition:
        filesize > 2MB and filesize < 3MB and
        (file_pe_header or file_elf_header) and
        all of ($key*)
}

rule MAL_Royal_ransomnote {
    meta:
        description = "Matches strings found in Royal ransom note sample."
        last_modified = "2024-01-21"
        author = "@petermstewart"
        DaysofYara = "21/100"

    strings:
        $a = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion"
        $b1 = "If you are reading this, it means that your system were hit by Royal ransomware"
        $b2 = "Please contact us via :"
        $b3 = "In the meantime, let us explain this case"
        $b4 = "It may seem complicated, but it is not!"
        $b5 = "Most likely what happened was that you decided to save some money on your security infrastructure"
        $b6 = "Alas, as a result your critical data was not only encrypted but also copied from your systems on a secure server"
        $b7 = "From there it can be published online"
        $b8 = "Then anyone on the internet from darknet criminals, ACLU journalists, Chinese government"
        $b9 = "and even your employees will be able to see your internal documentation: personal data, HR reviews, internal lawsuitsand complains, financial reports, accounting, intellectual property, and more"
        $b10 = "Fortunately we got you covered!"
        $b11 = "Royal offers you a unique deal.For a modest royalty(got it; got it ? )"
        $b12 = "for our pentesting services we will not only provide you with an amazing risk mitigation service"
        $b13 = "covering you from reputational, legal, financial, regulatory, and insurance risks, but will also provide you with a security review for your systems"
        $b14 = "To put it simply, your files will be decrypted, your data restoredand kept confidential, and your systems will remain secure"
        $b15 = "Try Royal today and enter the new era of data security"
        $b16 = "We are looking to hearing from you soon"

    condition:
        filesize < 5KB and
        1 of ($a*) and
        13 of ($b*)
}

rule MAL_Kuiper_strings {
    meta:
        description = "Matches strings found in Stairwell analysis blog post of Kuiper ransomware."
        last_modified = "2024-01-22"
        author = "@petermstewart"
        DaysofYara = "22/100"
        ref = "https://stairwell.com/resources/kuiper-ransomware-analysis-stairwells-technical-report/"

    strings:
        $a1 = "kuiper"
        $a2 = "README_TO_DECRYPT.txt"
        $a3 = "vssadmin delete shadows /all /quiet"
        $a4 = "wevtutil cl application"
        $a5 = "wbadmin delete catalog -quiet"
        $a6 = "bcdedit /set {default} recoveryenabled No"
        $a7 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest"
        $a8 = "wevtutil cl securit"
        $a9 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
        $a10 = "wbadmin DELETE SYSTEMSTATEBACKUP"
        $a11 = "wevtutil cl system"
        $a12 = "vssadmin resize shadowstorage /for="
        $a13 = "\\C$\\Users\\Public\\safemode.exe"
        $a14 = "process call create \"C:\\Users\\Public\\safemode.exe -reboot no\""

    condition:
        file_pe_header and
        10 of them
}

rule MAL_Kuiper_ransomnote {
    meta:
        description = "Matches strings found in Stairwell analysis blog post of Kuiper ransomware."
        last_modified = "2024-01-23"
        author = "@petermstewart"
        DaysofYara = "23/100"
        ref = "https://stairwell.com/resources/kuiper-ransomware-analysis-stairwells-technical-report/"

    strings:
        $tox = "D27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1B9803AAC6ECF9"
        $email = "kuipersupport@onionmail.org"
        $a1 = "Your network has been compromised! All your important data has been encrypted!"
        $a2 = "There is  only one way to get your data back to normal:"
        $a3 = "1. Contact us as soon as possible to avoid damages and losses from your business."
        $a4 = "2. Send to us any encrypted file of your choice and your personal key."
        $a5 = "3. We will decrypt 1 file for test (maximum file size = 1 MB), its guaranteed that we can decrypt your files."
        $a6 = "4. Pay the amount required in order to restore your network back to normal."
        $a7 = "5. We will then send you our software to decrypt and will guide you through the whole restoration of your network."
        $a8 = "We prefer Monero (XMR) - FIXED PRICE"
        $a9 = "We accept Bitcoin (BTC) - 20% extra of total payment!"
        $a10 = "WARNING!"
        $a11 = "Do not rename encrypted data."
        $a12 = "Do not try to decrypt using third party software, it may cause permanent data loss not being able to recover."
        $a13 = "Contact information:"
        $a14 = "In order to contact us, download with the following software: https://qtox.github.io or https://tox.chat/download.html"
        $a15 = "Then just add us in TOX:"
        $a16 = "Your personal id:"
        $a17 = "--------- Kuiper Team ------------"

    condition:
        filesize < 5KB and
        15 of them
}

rule MAL_BlackSuit_strings {
    meta:
        description = "Matches strings found in open-source reporting on BlackSuit Windows and Linux ransomware."
        last_modified = "2024-01-24"
        author = "@petermstewart"
        DaysofYara = "24/100"
        sha256 = "90ae0c693f6ffd6dc5bb2d5a5ef078629c3d77f874b2d2ebd9e109d8ca049f2c"
        sha256 = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
        ref = "https://twitter.com/siri_urz/status/1653692714750279681"
        ref = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
        ref = "https://www.trendmicro.com/en_us/research/23/e/investigating-blacksuit-ransomwares-similarities-to-royal.html"

    strings:
        $a = "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion"
        $b1 = "Good whatever time of day it is!"
        $b2 = "Your safety service did a really poor job of protecting your files against our professionals."
        $b3 = "Extortioner named  BlackSuit has attacked your system."
        $b4 = "As a result all your essential files were encrypted and saved at a secure server for further use and publishing on the Web into the public realm."
        $b5 = "Now we have all your files like: financial reports, intellectual property, accounting, law actionsand complaints, personal files and so on and so forth."
        $b6 = "We are able to solve this problem in one touch."
        $b7 = "We (BlackSuit) are ready to give you an opportunity to get all the things back if you agree to makea deal with us."
        $b8 = "You have a chance to get rid of all possible financial, legal, insurance and many others risks and problems for a quite small compensation."
        $b9 = "You can have a safety review of your systems."
        $b10 = "All your files will be decrypted, your data will be reset, your systems will stay in safe."
        $b11 = "Contact us through TOR browser using the link:"

    condition:
        (file_pe_header or file_elf_header) and
        $a and
        8 of ($b*)
}

rule MAL_BlackSuit_ransomnote {
    meta:
        description = "Matches strings found in open-source reporting of BlackSuit ransom notes."
        last_modified = "2024-01-25"
        author = "@petermstewart"
        DaysofYara = "25/100"
        ref = "https://twitter.com/siri_urz/status/1653692714750279681"
        ref = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
        ref = "https://www.trendmicro.com/en_us/research/23/e/investigating-blacksuit-ransomwares-similarities-to-royal.html"

    strings:
        $a = "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion"
        $b1 = "Good whatever time of day it is!"
        $b2 = "Your safety service did a really poor job of protecting your files against our professionals."
        $b3 = "Extortioner named  BlackSuit has attacked your system."
        $b4 = "As a result all your essential files were encrypted and saved at a secure server for further use and publishing on the Web into the public realm."
        $b5 = "Now we have all your files like: financial reports, intellectual property, accounting, law actionsand complaints, personal files and so on and so forth."
        $b6 = "We are able to solve this problem in one touch."
        $b7 = "We (BlackSuit) are ready to give you an opportunity to get all the things back if you agree to makea deal with us."
        $b8 = "You have a chance to get rid of all possible financial, legal, insurance and many others risks and problems for a quite small compensation."
        $b9 = "You can have a safety review of your systems."
        $b10 = "All your files will be decrypted, your data will be reset, your systems will stay in safe."
        $b11 = "Contact us through TOR browser using the link:"

    condition:
        filesize < 5KB and
        $a and
        8 of ($b*)
}

rule MAL_TurtleRansom_strings {
    meta:
        description = "Matches strings found in Windows, ELF, and MachO Turtle ransomware samples."
        last_modified = "2024-01-26"
        author = "@petermstewart"
        DaysofYara = "26/100"
        sha256 = "b384155b74845beeea0f781c9c216c69eceb018520d819dd09823cff6ef0e7de"
        sha256 = "f5b9b80f491e5779f646d2510a2c9c43f3072c45302d271798c4875544ace4f2"
        sha256 = "df5f7570bf0b1f99f33c31913ab9f25b9670286e8e2462278aea2157f8173a68"
        sha256 = "b5ab9c61c81dfcd2242b615c9af2cb018403c9a784b7610b39ed56222d669297"
        sha256 = "a4789e0b79a8bac486fbc3b0f00b6dcbaac6854e621d40fc3005d23f83d2e5ec"
        sha256 = "5f9cd91d8d1dcfe2f6cf4c6995ad746694ce57023dfb82b1cd6af5697113d1b0"
        sha256 = "a48af4a62358831fe5376aa52db1a3555b0c93c1665b242c0c1f49462f614c56"
        sha256 = "62f84afdab28727ab47b5c1e4af92b33dc2b11e55dca7b097fe94da5bcc9ec4e"
        sha256 = "f14ef1c911deb8714d1bb501064505c13237049ac51f0a657da4b0bf11f5f59e"
        sha256 = "65eea957148d75c29213dff0c5465c6dc1db266437865538cfe8744c2436f5e1"
        sha256 = "00b52a5905e042a9a9f365f7e5404f420ae26f463f24c069d6076e9094f61a8e"
        sha256 = "52337055cca751b8b2b716a1c8f3ba179ddd74b268b67641ade223d3d3cf773d"
        ref = "https://objective-see.org/blog/blog_0x76.html"

    strings:
        $a1 = "D:/VirTest/TurmiRansom/main.go"
        $a2 = "VirTest/TurmiRansom"
        $a3 = "TurmiRansom/main.go"
        $b1 = "TURTLERANSv0"
        $b2 = "wugui123"
        $b3 = "main..inittask"
        $b4 = "main.en0cr0yp0tFile"
        $b5 = "main.main"
        $b6 = "main.main.func1"

    condition:
        (file_pe_header or
        file_elf_header or
        file_macho_header) and
        2 of ($a*) and
        all of ($b*)
}

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
        (file_pe_header or
        file_elf_header or
        file_macho_header) and
        2 of them
}

rule HUNT_Signal_Desktop_File_References {
    meta:
        description = "Contains references to sensitive database and key files used by Signal desktop application."
        last_modified = "2024-01-28"
        author = "@petermstewart"
        DaysofYara = "28/100"
        ref = "https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/"
        ref = "https://www.bleepingcomputer.com/news/security/signal-desktop-leaves-message-decryption-key-in-plain-sight/"

    strings:
        $win_db = "\\AppData\\Roaming\\Signal\\sql\\db.sqlite" nocase ascii wide
        $win_key = "\\AppData\\Roaming\\Signal\\config.json" nocase ascii wide
        $lin_db = "config/Signal/sql/db.sqlite" nocase ascii wide
        $lin_key = "config/Signal/config.json" nocase ascii wide
        $macos_db = "/Signal/sql/db.sqlite" nocase ascii wide
        $macos_key = "/Signal/config.json" nocase ascii wide

    condition:
        (file_pe_header or
        file_elf_header or
        file_macho_header) and
        2 of them
}

rule MAL_BumbleBee_PowerShell_strings {
    meta:
        description = "Matches strings found in BumbleBee PowerShell loaders."
        last_modified = "2024-01-29"
        author = "@petermstewart"
        DaysofYara = "29/100"
        sha256 = "0ff8988d76fc6bd764a70a7a4f07a15b2b2c604138d9aadc784c9aeb6b77e275"
        sha256 = "9b6125e1aa889f2027111106ee406d08a21c894a83975b785a2b82aab3e2ac52"
        sha256 = "2102214c6a288819112b69005737bcfdf256730ac859e8c53c9697e3f87839f2"
        sha256 = "e9a1ce3417838013412f81425ef74a37608754586722e00cacb333ba88eb9aa7"

    strings:
        $a1 = "[System.Convert]::FromBase64String" ascii wide
        $a2 = "System.IO.Compression.GZipStream" ascii wide
        $elem = "$elem" ascii wide
        $invoke1 = ".Invoke(0,1)" ascii wide
        $invoke2 = ".Invoke(0,\"H\")" ascii wide

    condition:
        filesize > 1MB and filesize < 10MB and
        all of ($a*) and
        #elem > 30 and
        #invoke1 > 30 and
        #invoke2 > 30
}

rule MAL_BumbleBee_DLL_strings {
    meta:
        description = "Matches strings found in BumbleBee DLL sample extracted from initial PowerShell loader."
        last_modified = "2024-01-30"
        author = "@petermstewart"
        DaysofYara = "30/100"
        sha256 = "39e300a5b4278a3ff5fe48c7fa4bd248779b93bbb6ade55e38b22de5f9d64c3c"

    strings:
        $a1 = "powershell -ep bypass -Command"
        $a2 = " -Command \"Wait-Process -Id "
        $a3 = "schtasks.exe /F /create /sc minute /mo 4 /TN \""
        $a4 = "/ST 04:00 /TR \"wscript /nologo"
        $b1 = "SELECT * FROM Win32_ComputerSystemProduct"
        $b2 = "SELECT * FROM Win32_ComputerSystem"
        $b3 = "SELECT * FROM Win32_OperatingSystem"
        $b4 = "SELECT * FROM Win32_NetworkAdapterConfiguration" wide
        $b5 = "SELECT * FROM Win32_NTEventlogFile" wide
        $b6 = "SELECT * FROM Win32_PnPEntity" wide

    condition:
        file_pe_header and
        3 of ($a*) and
        4 of ($b*)
}

rule MAL_Lemonduck_strings {
    meta:
        description = "Matches strings found in Lemonduck cryptominer samples."
        last_modified = "2024-01-31"
        author = "@petermstewart"
        DaysofYara = "31/100"
        sha256 = "a5de49d6b14b04ba854246e1945ea1cfc8a7e7e254d0974efaba6415922c756f"

    strings:
        $a1 = "stratum+tcp"
        $a2 = "stratum+ssl"
        $b1 = "\"donate-level\":"
        $b2 = "\"health-print-time\":"
        $b3 = "\"retry-pause\":"
        $b4 = "\"nicehash\":"
        $b5 = "\"coin\":"
        $b6 = "\"randomx\":"
        $b7 = "\"opencl\":"
        $b8 = "\"cuda\":"
        $b9 = "This is a test This is a test This is a test"

    condition:
        (file_pe_header or file_elf_header) and
        1 of ($a*) and
        8 of ($b*)
}

rule TTP_cryptominer_stratum_strings {
    meta:
        description = "Matches stratum URL strings commonly found in cryptominers."
        last_modified = "2024-02-01"
        author = "@petermstewart"
        DaysofYara = "32/100"

    strings:
        $a1 = "stratum+tcp" ascii wide
        $a2 = "stratum+udp" ascii wide
        $a3 = "stratum+ssl" ascii wide

    condition:
        (file_pe_header or
        file_elf_header or
        file_macho_header) and
        any of them
}

rule MAL_Nighthawk_bytes {
    meta:
        description = "Matches hex byte pattern referenced in Proofpoint blog reversing Nighthawk malware."
        last_modified = "2024-02-02"
        author = "@petermstewart"
        DaysofYara = "33/100"
        ref = "https://web.archive.org/web/20221122125826/https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
        sha256 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
        sha256 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"

    strings:
        //   { 48 8d 0d f9 ff ff ff 51 5a 48 81 c1 20 4e 00 00 48 81 c2 64 27 00 00 ff e2 }
        $a = { 48 8d 0d ?? ff ff ff ?? ?? ?? ?? ?? ?? ?? 00 00 }

    condition:
        filesize > 500KB and filesize < 1MB and
        file_pe_header and
        $a
}

rule MAL_BRC4_string_obfuscation_bytes {
    meta:
        description = "Matches hex byte pattern used to obfuscate strings in BRC4 samples."
        last_modified = "2024-02-03"
        author = "@petermstewart"
        DaysofYara = "34/100"
        sha256 = "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe"
        sha256 = "973f573cab683636d9a70b8891263f59e2f02201ffb4dd2e9d7ecbb1521da03e"

    strings:
        $a1 = { 50 48 B8 74 00 20 00 64 00 6F 00 50 48 } //PH,t. .d.o.PH
        $a2 = { 50 48 B8 6E 00 73 00 68 00 6F 00 50 48 } //PH,n.s.h.o.PH
        $a3 = { 50 48 B8 63 00 72 00 65 00 65 00 50 48 } //PH,c.r.e.e.PH
        $b1 = { 50 48 B8 69 00 6D 00 61 00 67 00 50 48 } //PH,i.m.a.g.PH
        $b2 = { 50 48 B8 32 64 2E 70 6E 67 00 00 50 48 } //PH,2d.png..PH
        $c1 = { 50 48 B8 6E 00 67 00 3A 00 20 00 50 48 } //PH,n.g.:. .PH
        $c2 = { 50 48 B8 65 00 72 00 79 00 69 00 50 48 } //PH,e.r.y.i.PH
        $c3 = { 50 48 B8 5D 00 20 00 51 00 75 00 50 48 } //PH,]. .Q.u.PH

    condition:
        file_pe_header and
        5 of them
}

rule MAL_Sliver_implant_strings {
    meta:
        description = "Matches strings found in open-source Sliver beacon samples."
        last_modified = "2024-02-04"
        author = "@petermstewart"
        DaysofYara = "35/100"
        sha256 = "6037eaaa80348d44a51950b45b98077b3aeb16c66a983a8cc360d079daaaf53e"
        sha256 = "98df535576faab0405a2eabcd1aac2c827a750d6d4c3d76a716c24353bedf0b5"
        sha256 = "789e5fcb242ee1fab8ed39e677d1bf26c7ce275ae38de5a63b4d902c58e512ec"

    strings:
        $a1 = "bishopfox/sliver"
        $a2 = "sliver/protobuf"
        $a3 = "protobuf/commonpbb"
        $b1 = "ActiveC2Fprotobuf:\"bytes,11,opt,name="
        $b2 = "ProxyURLFprotobuf:\"bytes,14,opt,name="
        $b3 = "BeaconJitterNprotobuf:\"varint,3,opt,name="
        $b4 = "BeaconIntervalRprotobuf:\"varint,2,opt,name="
        $b5 = "BeaconIDEprotobuf:\"bytes,8,opt,name="
        $b6 = "BeaconID"
        $b7 = "GetBeaconJitter"
        $b8 = "BeaconRegister"

    condition:
        (filesize > 5MB and filesize < 20MB) and
        (file_pe_header or
        file_elf_header or
        file_macho_header) and
        2 of ($a*) or
        6 of ($b*)
}

rule MAL_Nimplant_strings {
    meta:
        description = "Matches strings found in open-source Nimplant samples."
        last_modified = "2024-02-05"
        author = "@petermstewart"
        DaysofYara = "36/100"
        sha256 = "4d7eb09c35a644118af702dd402fd9f5a75e490d33e86b6746e6eb6112c5caa7"
        sha256 = "90a5e330d411d84a09ef4af07d2b9c808acc028a91fa7e1d57c4f063e91fad49"
        ref = "https://github.com/chvancooten/NimPlant"

    strings:
        $ver = "NimPlant v"
        $header1 = "@Content-Type"
        $header2 = "@X-Identifier"
        $header3 = "@User-Agent"
        $cmd1 = "getLocalAdm"
        $cmd2 = "getAv"

    condition:
        file_pe_header and
        filesize > 300KB and filesize < 1MB and
        all of them
}

rule MAL_Mythic_Apollo_strings {
    meta:
        description = "Matches strings found in samples of the Windows Apollo agent used by the open-source Mythic framework."
        last_modified = "2024-02-06"
        author = "@petermstewart"
        DaysofYara = "37/100"
        sha256 = "bf3d47335b7c10f655987cfdefecdb2856c0ac90f2f1cedcd67067760a80aa98"
        sha256 = "67b2c1c5d96a7c70b2bc111ace08b35e0db63bef40534dc50a692d46f832d61a"
        ref = "https://github.com/MythicAgents/apollo"

    strings:
        $pdb = "Apollo.pdb"
        $a = "ApolloInterop"
        $b1 = "ApolloTrackerUUID"
        $b2 = "Apollo.Peers.SMB"
        $b3 = "Apollo.Peers.TCP"
        $b4 = "C2ProfileData"
        $b5 = "mythicFileId"
        $b6 = "IMythicMessage"
        $b7 = ".MythicStructs"
        $b8 = ".ApolloStructs"
        $b9 = "Apollo.Api"
        $b10 = "ApolloLogonInformation"

    condition:
        file_pe_header and
        ($pdb and #a > 15) or
        ($a and (6 of ($b*)))
}

rule MAL_Mythic_Apfell_strings {
    meta:
        description = "Matches strings found in samples of the macOS Apfell Javascript agent used by the open-source Mythic framework."
        last_modified = "2024-02-07"
        author = "@petermstewart"
        DaysofYara = "38/100"
        sha256 = "8962ad7c608962c637637b9d3aef101a87cfb71873210046d5a49cfa6f47a712"
        ref = "https://github.com/MythicAgents/apfell"

    strings:
        $a1 = "C2.checkin(ip,apfell.pid,apfell.user,ObjC.unwrap(apfell.procInfo.hostName),apfell.osVersion,"
        $a2 = "return this.interval + (this.interval * (this.get_random_int(this.jitter)/100));"
        $a3 = "let info = {'ip':ip,'pid':pid,'user':user,'host':host,'uuid':apfell.uuid, \"os\":os, \"architecture\": arch, \"domain\": domain, \"action\": \"checkin\"};"
        $b1 = "\"user\": apfell.user,"
        $b2 = "\"fullName\": apfell.fullName,"
        $b3 = "\"ips\": apfell.ip,"
        $b4 = "\"hosts\": apfell.host,"
        $b5 = "\"environment\": apfell.environment,"
        $b6 = "\"uptime\": apfell.uptime,"
        $b7 = "\"args\": apfell.args,"
        $b8 = "\"pid\": apfell.pid,"
        $b9 = "\"apfell_id\": apfell.id,"
        $b10 = "\"payload_id\": apfell.uuid"
        $c1 = "-IMPLANT INFORMATION-"
        $c2 = "-Base C2 INFORMATION-"
        $c3 = "-RESTFUL C2 mechanisms -"
        $c4 = "- INSTANTIATE OUR C2 CLASS BELOW HERE IN MAIN CODE-"
        $c5 = "-SHARED COMMAND CODE -"
        $c6 = "-GET IP AND CHECKIN -"
        $c7 = "-MAIN LOOP -"
        $c8 = "//To create your own C2, extend this class and implement the required functions"
        $c9 = "//gets a file from the apfell server in some way"
        $c10 = "//there is a 3rd slash, so we need to splice in the port"
        $c11 = "//generate a time that's this.interval += (this.interval * 1/this.jitter)"
        $c12 = "// now we need to prepend the IV to the encrypted data before we base64 encode and return it"
        $c13 = "// Encrypt our initial message with sessionID and Public key with the initial AES key"
        $c14 = "//depending on the amount of data we're sending, we might need to chunk it"
        $c15 = "//if we do need to decrypt the response though, do that"
        $c16 = "// don't spin out crazy if the connection fails"
        $c17 = "// always round up to account for chunks that are < chunksize;"
        $c18 = "//simply run a shell command via doShellScript and return the response"
        $c19 = "//  so I'll just automatically fix this so it's not weird for the operator"
        $c20 = "//  params should be {\"cmds\": \"cmd1 cmd2 cmd3\", \"file_id\": #}"

    condition:
        (all of ($a*) and 8 of ($b*)) or
        (15 of ($c*))
}

rule MAL_Mythic_Athena_strings {
    meta:
        description = "Matches strings found in samples of the Athena agent used by the open-source Mythic framework."
        last_modified = "2024-02-08"
        author = "@petermstewart"
        DaysofYara = "39/100"
        sha256 = "8075738035ac361d50db2c2112a539acc3f1ad4d4ed5f971b2e18c687fc029da"
        sha256 = "ce66c7487e56722f34e5fd0fea167f9c562a0bbb0d13128b0313e4d3eabff697"
        ref = "https://github.com/MythicAgents/athena"

    strings:
        $a = "Athena"
        $b1 = "\"Athena.Commands\":"
        $b2 = "\"Athena.Forwarders.SMB\":"
        $c1 = "\"cat\":"
        $c2 = "\"drives\":"
        $c3 = "\"get-clipboard\":"
        $c4 = "\"get-localgroup\":"
        $c5 = "\"get-sessions\":"
        $c6 = "\"get-shares\":"
        $c7 = "\"hostname\":"
        $c8 = "\"ifconfig\":"
        $c9 = "\"ls\":"
        $c10 = "\"mkdir\":"
        $c11 = "\"mv\":"
        $c12 = "\"ps\":"
        $c13 = "\"pwd\":"
        $c14 = "\"rm\":"
        $c15 = "\"shell\":"
        $c16 = "\"shellcode\":"
        $c17 = "\"whoami\":"

    condition:
        file_pe_header and
        #a > 100 and
        all of ($b*) and
        8 of ($c*)
}

rule MAL_CobaltStrike_Powershell_loader {
    meta:
        description = "Matches strings found in CobaltStrike PowerShell loader samples."
        last_modified = "2024-02-09"
        author = "@petermstewart"
        DaysofYara = "40/100"
        sha256 = "9c9e8841d706406bc23d05589f77eec6f8df6d5e4076bc6a762fdb423bfe8c24"
        sha256 = "6881531ab756d62bdb0c3279040a5cbe92f9adfeccb201cca85b7d3cff7158d3"
        ref = "https://medium.com/@cybenfolland/deobfuscating-a-powershell-cobalt-strike-beacon-loader-c650df862c34"
        ref = "https://forensicitguy.github.io/inspecting-powershell-cobalt-strike-beacon/"

    strings:
        $a1 = "=New-Object IO.MemoryStream("
        $a2 = "[Convert]::FromBase64String("
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        $b1 = "Set-StrictMode -Version 2"
        $b2 = "$DoIt = @'"
        $b3 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($DoIt))"
        $b4 = "start-job { param($a) IEX $a }"

    condition:
        all of ($a*) or
        all of ($b*)
}

rule MAL_CobaltStrike_Powershell_loader_base64 {
    meta:
        description = "Matches base64-encoded strings found in CobaltStrike PowerShell loader commands."
        last_modified = "2024-02-10"
        author = "@petermstewart"
        DaysofYara = "41/100"

    strings:
        $a1 = "=New-Object IO.MemoryStream(" base64 wide
        $a2 = "[Convert]::FromBase64String(" base64 wide
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()" base64 wide

    condition:
        all of them
}

rule MAL_CobaltStrike_HTA_loader {
    meta:
        description = "Matches strings found in CobaltStrike HTA loader samples."
        last_modified = "2024-02-11"
        author = "@petermstewart"
        DaysofYara = "42/100"
        sha256 = "2c683d112d528b63dfaa7ee0140eebc4960fe4fad6292c9456f2fbb4d2364680"
        ref = "https://embee-research.ghost.io/malware-analysis-decoding-a-simple-hta-loader/"

    strings:
        $header = "<script>"
        $a1 = "%windir%\\\\System32\\\\"
        $a2 = "/c powershell -w 1 -C"
        $b1 = "-namespace Win32Functions" base64 wide
        $b2 = "[Byte[]];[Byte[]]$" base64 wide
        $b3 = "{Start-Sleep 60};" base64 wide
        $b4 = "[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(" base64 wide
        $b5 = "\\syswow64\\WindowsPowerShell\\v1.0\\powershell\";iex" base64 wide
        $b6 = "else{;iex \"& powershell" base64 wide

    condition:
        $header at 0 and
        all of them
}

rule MAL_XMRig_strings {
    meta:
        description = "Matches strings found in XMRig cryptominer samples."
        last_modified = "2024-02-14"
        author = "@petermstewart"
        DaysofYara = "45/100"
        sha256 = "3c54646213638e7bd8d0538c28e414824f5eaf31faf19a40eec608179b1074f1"

    strings:
        $a1 = "Usage: xmrig [OPTIONS]"
        $a2 = "mining algorithm https://xmrig.com/docs/algorithms"
        $a3 = "username:password pair for mining server"
        $a4 = "--rig-id=ID"
        $a5 = "control donate over xmrig-proxy feature"
        $a6 = "https://xmrig.com/benchmark/%s"
        $a7 = "\\xmrig\\.cache\\"
        $a8 = "XMRIG_INCLUDE_RANDOM_MATH"
        $a9 = "XMRIG_INCLUDE_PROGPOW_RANDOM_MATH"
        $a10 = "'h' hashrate, 'p' pause, 'r' resume, 's' results, 'c' connection"

    condition:
        7 of them
}

rule HUNT_StripedFly {
    meta:
        description = "Matches strings found in Kaspersky Labs analysis of StripedFly malware."
        last_modified = "2024-02-15"
        author = "@petermstewart"
        DaysofYara = "46/100"
        ref = "https://securelist.com/stripedfly-perennially-flying-under-the-radar/110903/"

    strings:
        $a1 = "gpiekd65jgshwp2p53igifv43aug2adacdebmuuri34hduvijr5pfjad.onion" ascii wide
        $a2 = "ghtyqipha6mcwxiz.onion" ascii wide
        $a3 = "ajiumbl2p2mjzx3l.onion" ascii wide
        $b1 = "HKCU\\Software\\Classes\\TypeLib" ascii wide
        $b2 = "uname -nmo" ascii wide
        $b3 = "%s; chmod +x %s; nohup sh -c \"%s; rm %s\" &>/dev/null" ascii wide
        $b4 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" ascii wide

    condition:
        (file_pe_header or file_elf_header) and
        1 of ($a*) and
        1 of ($b*)
}

rule MAL_AbyssLocker_Lin_strings {
    meta:
        description = "Matches strings found in SentinelOne analysis of Linux variant of the Abyss Locker ransomware."
        last_modified = "2024-02-16"
        author = "@petermstewart"
        DaysofYara = "47/100"
        ref = "https://www.sentinelone.com/anthology/abyss-locker/"

    strings:
        $a1 = "Usage:%s [-m (5-10-20-25-33-50) -v -d] Start Path"
        $b1 = "esxcli vm process list"
        $b2 = "esxcli vm process kill -t=force -w=%d"
        $b3 = "esxcli vm process kill -t=hard -w=%d"
        $b4 = "esxcli vm process kill -t=soft -w=%d"
        $c1 = ".crypt" fullword
        $c2 = "README_TO_RESTORE"

    condition:
        file_elf_header and
        all of them
}

rule MAL_AbyssLocker_ransomnote {
    meta:
        description = "Matches strings found in SentinelOne analysis of Abyss Locker note."
        last_modified = "2024-02-17"
        author = "@petermstewart"
        DaysofYara = "48/100"
        ref = "https://www.sentinelone.com/anthology/abyss-locker/"

    strings:
        $a1 = "Your company Servers are locked and Data has been taken to our servers. This is serious."
        $a2 = "Good news:"
        $a3 = "100% of your Server system and Data will be restored by our Decryption Tool;"
        $a4 = "for now, your data is secured and safely stored on our server;"
        $a5 = "nobody in the world is aware about the data leak from your company except you and Abyss Locker team."
        $a6 = "Want to go to authorities for protection?"
        $a7 = "they will do their job properly, but you will not get any win points out of it, only headaches;"
        $a8 = "they will never make decryption for data or servers"
        $a9 = "Also, they will take all of your IT infrastructure as a part of their procedures"
        $a10 = "but still they will not help you at all."
        $a11 = "Think you can handle it without us by decrypting your servers and data using some IT Solution from third-party non-hackers"

    condition:
        filesize < 5KB and
        8 of them
}

rule HUNT_nopsled_8 {
    meta:
        description = "Matches 8 repeated no-operation hex bytes - 0x90"
        last_modified = "2024-02-18"
        author = "@petermstewart"
        DaysofYara = "49/100"
        
    strings:
        $a = { 90 90 90 90 90 90 90 90 }

    condition:
        filesize < 5MB and
        $a
}

rule HUNT_nopsled_16 {
    meta:
        description = "Matches 16 repeated no-operation hex bytes - 0x90"
        last_modified = "2024-02-18"
        author = "@petermstewart"
        DaysofYara = "49/100"
        
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        filesize < 5MB and
        $a
}

rule HUNT_nopsled_32 {
    meta:
        description = "Matches 32 repeated no-operation hex bytes - 0x90"
        last_modified = "2024-02-18"
        author = "@petermstewart"
        DaysofYara = "49/100"
        
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        filesize < 5MB and
        $a
}

rule TTP_BITS_Download_command {
    meta:
        description = "Matches strings commonly found when creating new BITS download jobs."
        last_modified = "2024-02-19"
        author = "@petermstewart"
        DaysofYara = "50/100"
        ref = "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"

    strings:
        $a = "bitsadmin /create" nocase ascii wide
        $b = "/addfile" nocase ascii wide
        $c = "/complete" nocase ascii wide
        $d = "http" nocase ascii wide

    condition:
        all of them
}

rule TTP_PowerShell_Download_command {
    meta:
        description = "Matches strings commonly found in PowerShell download cradles."
        last_modified = "2024-02-20"
        author = "@petermstewart"
        DaysofYara = "51/100"
        ref = "https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters"

    strings:
        $a = "powershell" nocase ascii wide
        $b = "IEX" nocase ascii wide
        $c = "New-Object" nocase ascii wide
        $d = "Net.Webclient" nocase ascii wide
        $e = ".downloadstring(" nocase ascii wide

    condition:
        4 of them
}

rule TTP_Certutil_Download_command {
    meta:
        description = "Matches strings commonly found in certutil.exe download commands."
        last_modified = "2024-02-21"
        author = "@petermstewart"
        DaysofYara = "52/100"
        ref = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download"

    strings:
        $a = "certutil" nocase ascii wide
        $b = "-urlcache" nocase ascii wide
        $c = "-split" nocase ascii wide
        $d = "http" nocase ascii wide

    condition:
        all of them
}

rule MAL_AsyncRAT_strings {
    meta:
        description = "Matches strings found in AsyncRAT samples."
        last_modified = "2024-02-22"
        author = "@petermstewart"
        DaysofYara = "53/100"
        sha256 = "00cdee79a9afc1bf239675ba0dc1850da9e4bf9a994bb61d0ec22c9fdd3aa36f"
        sha256 = "774e4d4af9175367bc3c7e08f4765778c58f1c66b46df88484a6aa829726f570"

    strings:
        $a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide
        $a2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $a3 = "bat.exe" wide
        $a4 = "Stub.exe" wide

    condition:
        file_pe_header and
        all of them
}

rule MAL_AsyncRAT_Github_release {
    meta:
        description = "Matches strings found in AsyncRAT Github release."
        last_modified = "2024-02-23"
        author = "@petermstewart"
        DaysofYara = "54/100"
        sha256 = "06899071233d61009a64c726a4523aa13d81c2517a0486cc99ac5931837008e5"
        ref = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        
    strings:
        $a1 = "NYAN-x-CAT"
        $a2 = "This program is distributed for educational purposes only."
        $a3 = "namespace AsyncRAT"
        $b1 = "[!] If you wish to upgrade to new version of AsyncRAT, You will need to copy 'ServerCertificate.p12'." wide
        $b2 = "[!] If you lose\\delete 'ServerCertificate.p12' certificate you will NOT be able to control your clients, You will lose them all." wide
        $b3 = "AsyncRAT | Dot Net Editor" wide
        $b4 = "XMR Miner | AsyncRAT" wide
        $b5 = "SEND A NOTIFICATION WHEN CLIENT OPEN A SPECIFIC WINDOW" wide
        $b6 = "Popup UAC prompt?" wide
        $b7 = "AsyncRAT | Unistall" wide
        $b8 = "recovered passwords successfully @ ClientsFolder" wide
    
    condition:
        file_pe_header and
        all of ($a*) or
        6 of ($b*)
}

rule PUP_THCHydra_strings {
    meta:
        description = "Matches strings found in the THC-Hydra network scanner."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        ref = "https://github.com/vanhauser-thc/thc-hydra"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    strings:
        $a1 = "hydra -P pass.txt target cisco-enable  (direct console access)"
        $a2 = "hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)"
        $a3 = "hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login foo, password bar)"
        $a4 = "hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass"
        $a5 = "hydra -L urllist.txt http-proxy-urlenum://target.com:3128/user:pass"
        $a6 = "USER hydra%d hydra %s :hydra"
        $a7 = "hydra rdp://192.168.0.1/firstdomainname -l john -p doe"
        $a8 = "User-Agent: Mozilla/4.0 (Hydra)"

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        all of them
}

rule PUP_THCHydra_default_icon {
    meta:
        description = "Matches the default icon resource section hash found in Windows THC-Hydra network scanner binaries."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        sha256 = "ee43a7be375ae2203b635c569652f182f381b426f80430ee495aa6a96f37b4e6"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    condition:
        uint16(0) == 0x5a4d and
        for any resource in pe.resources:
        (
            hash.md5(resource.offset, resource.length) == "7835bdbf054e7ba813fa0203aa1c5e36"
        )
}

rule MAL_NoVirus_strings {
    meta:
        description = "Matches strings found in ransomware sample uploaded to VirusTotal with filename 'no virus.exe'."
        last_modified = "2024-02-25"
        author = "@petermstewart"
        DaysofYara = "56/100"
        sha256 = "015e546f3ac1350c5b68fedc89e16334a4e456092228e691f054c1a86fefb6c6"
        ref = "https://x.com/malwrhunterteam/status/1745182178474885199"

    strings:
        $a1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide
        $a2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" wide
        $a3 = "wbadmin delete catalog -quiet" wide
        $b1 = "read_it.txt" wide
        $b2 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" wide
        $c1 = "Don't worry, you can return all your files!" wide
        $c2 = "All your files like documents, photos, databases and other important are encrypted" wide
        $c3 = "You must follow these steps To decrypt your files" wide
        $c4 = "1) CONTACT US Telegram @CryptoKeeper_Support" wide
        $c5 = "2) Obtain Bitcoin (You have to pay for decryption in Bitcoins." wide
        $c6 = "After payment we will send you the tool that will decrypt all your files.)" wide
        $c7 = "3) Send 500$ worth of btc to the next address:" wide
        $c8 = "17Ym1FfiuXGGWr1SN6enUEEZUwnsuNMUDa" wide

    condition:
        file_pe_header and
        8 of them
}

rule MAL_PrivateLoader_strings {
    meta:
        description = "Matches strings found in PrivateLoader malware samples."
        last_modified = "2024-02-26"
        author = "@petermstewart"
        DaysofYara = "57/100"
        sha256 = "077225467638a420cf29fb9b3f0241416dcb9ed5d4ba32fdcf2bf28f095740bb"
        sha256 = "27c1ed01c767f504642801a7e7a7de8d87dbc87dee88fbc5f6adb99f069afde4"

    strings:
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" ascii wide
        $b1 = ".?AVBase@Rijndael@CryptoPP@@" ascii
        $b2 = ".?AVCannotFlush@CryptoPP@@" ascii
        $b3 = ".?AVBase64Decoder@CryptoPP@@" ascii
        $b4 = ".?AVCBC_Encryption@CryptoPP@@" ascii
        $b5 = "Cleaner" ascii
        $c1 = "Content-Type: application/x-www-form-urlencoded" wide
        $c2 = "https://ipinfo.io/" wide
        $c3 = "https://db-ip.com/" wide
        $c4 = "https://www.maxmind.com/en/locate-my-ip-address" wide
        $c5 = "https://ipgeolocation.io/" wide

    condition:
        file_pe_header and
        ($ua and 4 of them) or
        all of ($b*) or
        all of ($c*)
}

rule MAL_Netwire_strings {
    meta:
        description = "Matches strings found in NetWire malware samples."
        last_modified = "2024-02-27"
        author = "@petermstewart"
        DaysofYara = "58/100"
        sha256 = "05a36b671efa242764695140c004dfff3e0ff9d11df5d74005b7c1c8c53d8f00"
        sha256 = "d2a60c0cb4dd0c53c48bc062ca754d94df400dee9b672cf8881f5a1eff5b4fbe"

    strings:
        $ua = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $a1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        $a2 = "Accept-Language: en-US,en;q=0.8"
        $a3 = "GET %s HTTP/1.1" 
        $b1 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1"
        $b2 = "DEL /s \"%s\" >nul 2>&1"
        $b3 = "call :deleteSelf&exit /b"
        $b4 = ":deleteSelf"
        $b5 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b"
        $b6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
        $c1 = "%6\\EWWnid\\PI0Wld\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
        $c2 = "%6\\PI0Wl4Ql\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
        $c3 = "%6\\PWlWSW\\a0CnWR\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
        $c4 = "%6\\vCRSdf\\vCRSdfc0Wg6d0\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
        $c5 = "%6\\Tsd0C MW85gC0d\\Tsd0C M5CVid\\mWn4R aC5C"

    condition:
        file_pe_header and
        12 of them
}

rule MAL_DarkComet_strings {
    meta:
        description = "Matches strings found in DarkComet malware samples."
        last_modified = "2024-02-28"
        author = "@petermstewart"
        DaysofYara = "59/100"
        sha256 = "3e10c254d6536cc63d286b53abfebbf53785e6509ae9fb569920747d379936f6"

    strings:
        $a1 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!"
        $a2 = "BTRESULTPing|Respond [OK] for the ping !|"
        $a3 = "BTRESULTClose Server|close command receive, bye bye...|"
        $a4 = "BTRESULTHTTP Flood|Http Flood task finished!|"
        $a5 = "BTRESULTMass Download|Downloading File...|"
        $a6 = "ERR|Cannot listen to port, try another one..|"

    condition:
        file_pe_header and
        all of them
}

rule MAL_SystemBC_Win_strings {
    meta:
        description = "Matches strings found in SystemBC malware Windows samples."
        last_modified = "2024-02-29"
        author = "@petermstewart"
        DaysofYara = "60/100"
        sha256 = "876c2b332d0534704447ab5f04d0eb20ff1c150fd60993ec70812c2c2cad3e6a"
        sha256 = "b9d6bf45d5a7fefc79dd567d836474167d97988fc77179a2c7a57f29944550ba"

    strings:
        $a1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
        $a2 = "GET %s HTTP/1.0"
        $a3 = "Host: %s"
        $a4 = "Connection: close"
        $b1 = "BEGINDATA"
        $b2 = "HOST1:"
        $b3 = "HOST2:"
        $b4 = "PORT1:"
        $b5 = "DNS:"
        $b6 = "-WindowStyle Hidden -ep bypass -file"

    condition:
        file_pe_header and
        all of ($a*) or
        5 of ($b*)
}

rule MAL_SystemBC_Lin_strings {
    meta:
        description = "Matches strings found in SystemBC malware Linux samples."
        last_modified = "2024-03-01"
        author = "@petermstewart"
        DaysofYara = "61/100"
        sha256 = "cf831d33e7ccbbdc4ec5efca43e28c6a6a274348bb7bac5adcfee6e448a512d9"
        sha256 = "b68bfd96f2690058414aaeb7d418f376afe5ba65d18ee4441398807b06d520fd"

    strings:
        $a1 = "Rc4_crypt" fullword
        $a2 = "newConnection" fullword
        $a3 = "/tmp/socks5.sh" fullword
        $a4 = "cat <(echo '@reboot echo" fullword
        $a5 = "socks5_backconnect" fullword

    condition:
        file_elf_header and
        2 of them
}

rule PUP_RMM_ScreenConnect_msi {
    meta:
        description = "Matches strings found in ScreenConnect MSI packages, often abused for unauthorised access."
        last_modified = "2024-03-02"
        author = "@petermstewart"
        DaysofYara = "62/100"
        sha256 = "80b6ec0babee522290588e324026f7c16e3de9d178b9e846ae976ab432058ce7"
        sha256 = "f8c2b122da9c9b217eada5a1e5fde92678925f1bb2ea847253538ffda274f0b9"

    strings:
        $a1 = "ScreenConnect.Client.dll"
        $a2 = "ScreenConnect.WindowsClient.exe"
        $a3 = "Share My Desktop"
        $a4 = "Grab a still image of the remote machine desktop"

    condition:
        file_msi and
        all of them
}

rule PUP_RMM_AnyDesk_exe {
    meta:
        description = "Matches AnyDesk remote management tool, often abused for unauthorised access."
        last_modified = "2024-03-03"
        author = "@petermstewart"
        DaysofYara = "63/100"
        sha256 = "5beab9f13976d174825f9caeedd64a611e988c69f76e63465ed10c014de4392a"
        sha256 = "7a719cd40db3cf7ed1e4b0d72711d5eca5014c507bba029b372ade8ca3682d70"

    strings:
        $pdb = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb"
        $a1 = "my.anydesk.com"
        $a2 = "AnyDesk Software GmbH" wide

    condition:
        file_pe_header and
        all of them
}

rule PUP_RMM_AteraAgent_msi {
    meta:
        description = "Matches strings found in AteraAgent remote management tool installer, often abused for unauthorised access."
        last_modified = "2024-03-04"
        author = "@petermstewart"
        DaysofYara = "64/100"
        sha256 = "91d9c73b804aae60057aa93f4296d39ec32a01fe8201f9b73f979d9f9e4aea8b"

    strings:
        $a1 = "AteraAgent"
        $a2 = "This installer database contains the logic and data required to install AteraAgent."

    condition:
        file_msi and
        all of them
}

rule HUNT_Mimizatz_ascii_art {
    meta:
        description = "Matches ascii art Mimikatz logo."
        last_modified = "2024-03-05"
        author = "@petermstewart"
        DaysofYara = "65/100"
        sha256 = "912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9"

    strings:
        $a1 = ".#####." ascii wide
        $a2 = ".## ^ ##."  ascii wide
        $a3 = "## / \\ ##" ascii wide
        $a4 = "## \\ / ##" ascii wide
        $a5 = "'## v ##'" ascii wide
        $a6 = "'#####'" ascii wide

    condition:
        all of them
}

rule HUNT_PDF_contains_TLP_marking {
    meta:
        description = "Finds PDF files which contain TLP marking strings."
        last_modified = "2024-03-07"
        author = "@petermstewart"
        DaysofYara = "67/100"
        ref = "https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage"

    strings:
        $a = "TLP:RED" ascii wide fullword
        $b = "TLP:AMBER+STRICT" ascii wide fullword
        $c = "TLP:AMBER" ascii wide fullword
        $d = "TLP:GREEN" ascii wide fullword
        $e = "TLP:CLEAR" ascii wide fullword

    condition:
        file_pdf_header and
        any of them
}

rule MAL_PingRAT_client_strings {
    meta:
        description = "Matches strings found in the PingRAT client binary and source code."
        last_modified = "2024-03-08"
        author = "@petermstewart"
        DaysofYara = "68/100"
        sha256 = "51bcb9d9b2e3d8292d0666df573e1a737cc565c0e317ba18cb57bd3164daa4bf"
        ref = "https://github.com/umutcamliyurt/PingRAT"

    strings:
        $a1 = "(Virtual) Network Interface (e.g., eth0)"
        $a2 = "Destination IP address"
        $a3 = "[+] ICMP listener started!"
        $b1 = "golang.org/x/net/icmp"
        $b2 = "golang.org/x/net/ipv4"
        $b3 = "os/exec"

    condition:
        all of them
}

rule MAL_PingRAT_server_strings {
    meta:
        description = "Matches strings found in the PingRAT server binary and source code."
        last_modified = "2024-03-09"
        author = "@petermstewart"
        DaysofYara = "69/100"
        sha256 = "81070ba18e6841ee7ec44b00bd33e8a44c8c1af553743eebcb0d44b47130b677"
        ref = "https://github.com/umutcamliyurt/PingRAT"

    strings:
        $a1 = "Listener (virtual) Network Interface (e.g. eth0)"
        $a2 = "Destination IP address"
        $a3 = "Please provide both interface and destination IP address."
        $a4 = "[+] ICMP C2 started!"
        $a5 = "[+] Command sent to the client:"
        $a6 = "[+] Stopping ICMP C2..."
        $b1 = "golang.org/x/net/icmp"
        $b2 = "golang.org/x/net/ipv4"
        $b3 = "os/signal"

    condition:
        all of them
}

rule PUP_AdvancedIPScanner_strings {
    meta:
        description = "Matches strings found in the Advanced IP Scanner installer, often abused by malicious actors."
        last_modified = "2024-03-10"
        author = "@petermstewart"
        DaysofYara = "70/100"
        sha256 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b"

    strings:
        $a1 = "This installer contains the logic and data to install Advanced IP Scanner"
        $a2 = "www.advanced-ip-scanner.com/link.php?"
        $a3 = "advanced ip scanner; install; network scan; ip scan; LAN"

    condition:
        file_pe_header and
        all of them
}

rule MAL_GAZPROM_strings {
    meta:
        description = "Matches strings found in Windows samples of GAZPROM ransomware."
        last_modified = "2024-03-11"
        author = "@petermstewart"
        DaysofYara = "71/100"
        sha256 = "5d61fcaa5ca55575eb82df8b87ab8d0a1d08676fd2085d4b7c91f4b16898d2f1"

    strings:
        $a = ".GAZPROM" wide
        $b1 = "Your files has been encrypted!"
        $b2 = "Need restore? Contact us:"
        $b3 = "Telegram @gazpromlock"
        $b4 = "Dont use any third party software for restoring your data!"
        $b5 = "Do not modify and rename encrypted files!"
        $b6 = "Decryption your files with the help of third parties may cause increased price."
        $b7 = "They add their fee to our and they usually fail or you can become a victim of a scam."
        $b8 = "We guarantee complete anonymity and can provide you with proof and"
        $b9 = "guaranties from our side and our best specialists make everything for restoring"
        $b10 = "but please should not interfere without us."
        $b11 = "If you dont contact us within 24 hours from encrypt your files - price will be higher."
        $b12 = "Your decrypt key:"

    condition:
        filesize > 200KB and filesize < 350KB and
        file_pe_header and
        $a and
        10 of ($b*)
}

rule MAL_GAZPROM_ransomnote {
    meta:
        description = "Matches strings found in GAZPROM ransomware samples."
        last_modified = "2024-03-12"
        author = "@petermstewart"
        DaysofYara = "72/100"

    strings:
        $a1 = "⠄⠄⠄⠄⠄⠄⢀⣤⣴⣶⡶⠖⠂⠉⠓⠶⣦⣄⠄⠄⠄⠄⠄⠄"
        $a2 = "⠄⠄⠄⠄⢀⣼⣿⣿⡿⠋⠈⠄⠄⠄⠄⠄⠈⠛⠷⣦⡀⠄⠄⠄"
        $a3 = "⠄⠄⠄⣴⣿⣿⠟⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢻⣆⠄⠄"
        $a4 = "⠄⠄⢸⣿⣿⠇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⡄⠄"
        $a5 = "⠄⠄⣾⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⠄"
        $a6 = "⠄⠄⣿⣿⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⠄"
        $a7 = "⢠⣶⣿⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣀⠄⠄⢸⡇"
        $a8 = "⠈⠟⣻⣿⡇⠄⠄⠠⣤⣴⣿⣿⣿⣷⡆⠄⣰⣿⣟⣛⣿⠆⢸⠃"
        $a9 = "⠄⠄⠘⣫⢳⡀⠄⠄⠄⠉⠈⠋⠉⠉⠑⠄⠉⠁⠉⠁⠁⠄⠘⠄"
        $a10 = "⠄⠄⠄⠪⣼⣷⣄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⡆⠄"
        $a11 = "⠄⠄⠄⠐⢻⣿⢿⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⠁⠄"
        $a12 = "⠄⠄⠄⠄⠄⣿⡏⢣⠄⠄⠄⠄⠄⠑⢶⣤⣤⠂⠄⠄⠄⡼⠄⠄"
        $a13 = "⠄⠄⠄⠄⠄⢸⣷⣄⠄⠄⠄⢀⣄⣀⣀⠉⢀⣀⡄⠄⢠⠇⠄⠄"
        $a14 = "⠄⠄⠄⢀⣴⠈⣿⣿⣦⡀⠄⠈⠱⣧⣭⣭⣭⠟⠁⢀⣼⣧⡀⠄"
        $a15 = "⣶⣶⣶⣿⡟⠄⠙⢿⣿⣿⣦⣄⡀⠄⠄⠄⠄⢀⠴⠋⣼⣿⣿⣷"
        $a16 = "⣿⣿⣿⣿⠇⠄⠄⠄⠙⢿⣿⣿⣿⣿⡿⠟⠋⠁⠄⠄⣿⣿⣿⣿"
        $a17 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
        $a18 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
        $a19 = "⣿⣿⣿⠄⠄⠈⠄⠄⠄⣿⣿⣿⠋⠄⠄⠄⠄⠄⢸⣿⣿⣿⣿⣿"
        $a20 = "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
        $b1 = "Your files has been encrypted"
        $b2 = "Telegram @gazpromlock"
        $b3 = "Your decrypt key:"

    condition:
        filesize < 5KB and
        21 of them
}

rule HUNT_GAZPROM_ascii_art {
    meta:
        description = "Matches ascii art found in GAZPROM ransomware samples."
        last_modified = "2024-03-12"
        author = "@petermstewart"
        DaysofYara = "72/100"
        sha256 = "5d61fcaa5ca55575eb82df8b87ab8d0a1d08676fd2085d4b7c91f4b16898d2f1"

    strings:
        $a1 = "⠄⠄⠄⠄⠄⠄⢀⣤⣴⣶⡶⠖⠂⠉⠓⠶⣦⣄⠄⠄⠄⠄⠄⠄"
        $a2 = "⠄⠄⠄⠄⢀⣼⣿⣿⡿⠋⠈⠄⠄⠄⠄⠄⠈⠛⠷⣦⡀⠄⠄⠄"
        $a3 = "⠄⠄⠄⣴⣿⣿⠟⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢻⣆⠄⠄"
        $a4 = "⠄⠄⢸⣿⣿⠇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⡄⠄"
        $a5 = "⠄⠄⣾⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⠄"
        $a6 = "⠄⠄⣿⣿⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⠄"
        $a7 = "⢠⣶⣿⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣀⠄⠄⢸⡇"
        $a8 = "⠈⠟⣻⣿⡇⠄⠄⠠⣤⣴⣿⣿⣿⣷⡆⠄⣰⣿⣟⣛⣿⠆⢸⠃"
        $a9 = "⠄⠄⠘⣫⢳⡀⠄⠄⠄⠉⠈⠋⠉⠉⠑⠄⠉⠁⠉⠁⠁⠄⠘⠄"
        $a10 = "⠄⠄⠄⠪⣼⣷⣄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⡆⠄"
        $a11 = "⠄⠄⠄⠐⢻⣿⢿⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⠁⠄"
        $a12 = "⠄⠄⠄⠄⠄⣿⡏⢣⠄⠄⠄⠄⠄⠑⢶⣤⣤⠂⠄⠄⠄⡼⠄⠄"
        $a13 = "⠄⠄⠄⠄⠄⢸⣷⣄⠄⠄⠄⢀⣄⣀⣀⠉⢀⣀⡄⠄⢠⠇⠄⠄"
        $a14 = "⠄⠄⠄⢀⣴⠈⣿⣿⣦⡀⠄⠈⠱⣧⣭⣭⣭⠟⠁⢀⣼⣧⡀⠄"
        $a15 = "⣶⣶⣶⣿⡟⠄⠙⢿⣿⣿⣦⣄⡀⠄⠄⠄⠄⢀⠴⠋⣼⣿⣿⣷"
        $a16 = "⣿⣿⣿⣿⠇⠄⠄⠄⠙⢿⣿⣿⣿⣿⡿⠟⠋⠁⠄⠄⣿⣿⣿⣿"
        $a17 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
        $a18 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
        $a19 = "⣿⣿⣿⠄⠄⠈⠄⠄⠄⣿⣿⣿⠋⠄⠄⠄⠄⠄⢸⣿⣿⣿⣿⣿"
        $a20 = "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"

    condition:
        all of them
}

rule TTP_delete_volume_shadow {
    meta:
        description = "Matches references to 'vssadmin delete' commands - used to remove Volume Shadow Copies."
        last_modified = "2024-03-13"
        author = "@petermstewart"
        DaysofYara = "73/100"

    strings:
        $a = "vssadmin delete" ascii wide nocase
        $b = "vssadmin.exe delete" ascii wide nocase

    condition:
        file_pe_header and
        any of them
}

rule TTP_clear_event_logs {
    meta:
        description = "Matches references to 'wevtutil' or 'Clear-Eventlog' - used to clear Windows Event Logs."
        last_modified = "2024-03-14"
        author = "@petermstewart"
        DaysofYara = "74/100"

    strings:
        $a = "wevtutil cl" ascii wide nocase
        $b = "wevtutil.exe cl" ascii wide nocase
        $c = "wevtutil clear log" ascii wide nocase
        $d = "wevtutil.exe clear log" ascii wide nocase
        $e = "Clear-EventLog" ascii wide nocase //PowerShell

    condition:
        file_pe_header and
        any of them
}

rule TTP_bcdedit_safeboot_cmd {
    meta:
        description = "Matches bcdedit command used to configure reboot to safemode - can be used to bypass security tools."
        last_modified = "2024-03-15"
        author = "@petermstewart"
        DaysofYara = "75/100"

    strings:
        $a = "bcdedit /set {default} safeboot" ascii wide nocase
        $b = "bcdedit.exe /set {default} safeboot" ascii wide nocase

    condition:
        file_pe_header and
        any of them
}

rule MAL_H0lyGh0st_SiennaPurple_strings {
    meta:
        description = "Matches strings found in SiennaPurple variant of H0lyGh0st ransomware binaries."
        last_modified = "2024-03-17"
        author = "@petermstewart"
        DaysofYara = "77/100"
        sha256 = "99fc54786a72f32fd44c7391c2171ca31e72ca52725c68e2dde94d04c286fccd"
        ref = "https://blogs.blackberry.com/en/2022/08/h0lygh0st-ransomware"

    strings:
        $pdb = "M:\\ForOP\\attack(utils)\\attack tools\\Backdoor\\powershell\\btlc_C\\Release\\btlc_C.pdb"
        $a1 = "matmq3z3hiovia3voe2tix2x54sghc3tszj74xgdy4tqtypoycszqzqd.onion"
        $a2 = "H0lyGh0st@mail2tor.com"
        $b1 = "We are <HolyGhost>"
        $b2 = "All your important files are stored and encrypted"
        $b3 = "Do not try to decrypt using third party software, it may cause permanent data lose"
        $b4 = "To Decrypt all device, Contact us"
        $b5 = "or install tor browser and visit"

    condition:
        file_pe_header and
        6 of them
}

rule MAL_H0lyGh0st_SiennaBlue_strings {
    meta:
        description = "Matches strings found in SiennaPurple variant of H0lyGh0st ransomware binaries."
        last_modified = "2024-03-18"
        author = "@petermstewart"
        DaysofYara = "78/100"
        sha256 = "f8fc2445a9814ca8cf48a979bff7f182d6538f4d1ff438cf259268e8b4b76f86"
        sha256 = "bea866b327a2dc2aa104b7ad7307008919c06620771ec3715a059e675d9f40af"
        ref = "https://blogs.blackberry.com/en/2022/08/h0lygh0st-ransomware"

    strings:
        $a = ".h0lyenc"
        $b1 = "Please Read this text to decrypt all files encrypted"
        $b2 = "We have uploaded all files to cloud"
        $b3 = "Don't worry, you can return all of your files immediately if you pay"
        $b4 = "If you want to restore all of your files, Send mail to"
        $b5 = "with your Id. Your ID is"
        $b6 = "Or install tor browser and contact us with your id or "
        $b7 = "(If all of pcs in your company are encrypted)"
        $b8 = "Our site : "
        $b9 = "H0lyGh0stWebsite"
        $b10 = "After you pay, We will send unlocker with decryption key"

    condition:
        file_pe_header and
        $a and
        7 of them
}

rule MAL_ChaosRansom_strings {
    meta:
        description = "Matches function name strings found in Chaos ransomware samples."
        last_modified = "2024-03-19"
        author = "@petermstewart"
        DaysofYara = "79/100"
        sha256 = "1ba5ab55b7212ba92a9402677e30e45f12d98a98f78cdcf5864a67d6c264d053"
        sha256 = "a98bc2fcbe8b3c7ea9df3712599a958bae0b689ae29f33ee1848af7a038d518a"

    strings:
        $a1 = "encryptionAesRsa"
        $a2 = "encryptedFileExtension"
        $a3 = "checkdeleteShadowCopies"
        $a4 = "checkdisableRecoveryMode"
        $a5 = "bytesToBeEncrypted"

    condition:
        file_pe_header and
        all of them
}

rule MAL_Remcos_strings {
    meta:
        description = "Matches strings found in Remcos RAT samples."
        last_modified = "2024-03-20"
        author = "@petermstewart"
        DaysofYara = "80/100"
        sha256 = "b3d7fad59a0ae75ffef9e05f47fc381b4adb716c498106482492e56c1b4370a7"
        sha256 = "9046b2e6ce92647474048c30439ab21ee69a46f6067dbaff67de729644120fad"

    strings:
        $a = "Remcos_Mutex_Inj"
        $b1 = "Uploading file to C&C: "
        $b2 = "Unable to delete: "
        $b3 = "Unable to rename file!"
        $b4 = "Browsing directory: "
        $b5 = "Offline Keylogger Started"
        $b6 = "Online Keylogger Started"
        $b7 = "[Chrome StoredLogins found, cleared!]"
        $b8 = "[Firefox StoredLogins cleared!]"
        $b9 = "Cleared all browser cookies, logins and passwords."
        $b10 = "[Following text has been pasted from clipboard:]"
        $b11 = "[End of clipboard text]"
        $b12 = "OpenCamera"
        $b13 = "CloseCamera"

    condition:
        file_pe_header and
        $a and
        10 of ($b*)
}

rule PUP_Cloudflare_tunnel_strings {
    meta:
        description = "Matches strings found in Cloudflare Tunnel client binaries, often abused by threat actors."
        last_modified = "2024-03-21"
        author = "@petermstewart"
        DaysofYara = "81/100"
        sha256 = "92ec16e1226249fcb7f07691a3e6d8fbb0f4482c786c4cff51b4ecab3e1a3a86"
        sha256 = "05cead663a846504ca20d73abede2e97c7cae59b3975fb6dbe89840d57abc5d7"
        ref = "https://github.com/cloudflare/cloudflared"

    strings:
        $a1 = "cloudflared connects your machine or user identity to Cloudflare's global network"
        $a2 = "Use Cloudflare Tunnel to expose private services to the Internet or to Cloudflare connected private users."
        $a3 = "[global options] [command] [command options]"

    condition:
        all of them
}

rule MAL_Cactus_strings {
    meta:
        description = "Matches strings found in Cactus ransomware samples."
        last_modified = "2024-03-22"
        author = "@petermstewart"
        DaysofYara = "82/100"
        sha256 = "1ea49714b2ff515922e3b606da7a9f01732b207a877bcdd1908f733eb3c98af3"
        sha256 = "c49b4faa6ac7b5c207410ed1e86d0f21c00f47a78c531a0a736266c436cc1c0a"

    strings:
        $a1 = "vssadmin delete shadows /all /quiet" wide
        $a2 = "WMIC shadowcopy delete" wide
        $a3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide
        $a4 = "bcdedit /set {default} recoveryenabled no" wide
        $a5 = "cAcTuS" wide
        $a6 = "CaCtUs.ReAdMe.txt" wide
        $a7 = "schtasks.exe /create /sc MINUTE /mo 5 /rl HIGHEST /ru SYSTEM /tn \"Updates Check Task\" /tr \"cmd /c cd C:\\ProgramData &&" wide
        $a8 = "C:\\Windows\\system32\\schtasks.exe /run /tn \"Updates Check Task\"" wide

    condition:
        file_pe_header and
        6 of them
}

rule MAL_Cactus_ransomnote {
    meta:
        description = "Matches strings found in ransom notes dropped by Cactus ransomware."
        last_modified = "2024-03-23"
        author = "@petermstewart"
        DaysofYara = "83/100"
        
    strings:
        $a1 = "cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion"
        $a2 = "sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion"
        $a3 = "cactus2tg32vfzd6mwok23jfeolh4yxrg2obzlsyax2hfuka3passkid.onion"
        $b1 = "encrypted by Cactus"
        $b2 = "Do not interrupt the encryption process"
        $b3 = "Otherwise the data may be corrupted"
        $b4 = "wait until encryption is finished"
        $b6 = "TOX (https://tox.chat):"
        $b7 = "7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421AE1D49ACEABB2"

    condition:
        filesize < 5KB and
        1 of ($a*) or
        5 of ($b*)
}

rule MAL_APT_SugarGhost_Loader_strings {
    meta:
        description = "Matches strings found in the DLL loader component of SugarGhost malware."
        last_modified = "2024-03-24"
        author = "@petermstewart"
        DaysofYara = "84/100"
        sha256 = "34cba6f784c8b68ec9e598381cd3acd11713a8cf7d3deba39823a1e77da586b3"
        ref = "https://blog.talosintelligence.com/new-sugargh0st-rat/"

    strings:
        $a1 = "The ordinal %u could not be located in the dynamic link library %s"
        $a2 = "File corrupted!. This program has been manipulated and maybe"
        $a3 = "it's infected by a Virus or cracked. This file won't work anymore."

    condition:
        filesize > 200MB and
        file_pe_header and
        all of them
}

rule MAL_Loader_KrustyLoader_strings {
    meta:
        description = "Matches strings found in KrustyLoader malware samples."
        last_modified = "2024-03-25"
        author = "@petermstewart"
        DaysofYara = "85/100"
        sha256 = "030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0"
        ref = "https://www.synacktiv.com/en/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises"

    strings:
        $a1 = "|||||||||||||||||||||||||||||||||||"
        $a2 = "/proc/self/exe"
        $a3 = "/tmp/"
        $a4 = "TOKIO_WORKER_THREADS"

    condition:
        file_elf_header and
        all of them
}

rule MAL_Yanluowang_strings {
    meta:
        description = "Matches function name strings found in Yanluowang ransomware samples."
        last_modified = "2024-03-26"
        author = "@petermstewart"
        DaysofYara = "86/100"
        sha256 = "49d828087ca77abc8d3ac2e4719719ca48578b265bbb632a1a7a36560ec47f2d"
        sha256 = "d11793433065633b84567de403c1989640a07c9a399dd2753aaf118891ce791c"

    strings:
        $a1 = "C:\\Users\\111\\Desktop\\wifi\\project\\ConsoleApplication2\\Release\\ConsoleApplication2.pdb"
        $a2 = "C:\\Users\\cake\\Desktop\\project-main\\project-main\\ConsoleApplication2\\cryptopp-master"
        $a3 = "Syntax: encrypt.exe [(-p,-path,--path)<path>]"
        $a4 = "yanluowang"

    condition:
        file_pe_header and
        all of them
}

rule MAL_Yanluowang_ransomnote {
    meta:
        description = "Matches strings found in Yanluowang ransom notes."
        last_modified = "2024-03-27"
        author = "@petermstewart"
        DaysofYara = "87/100"

    strings:
        $a1 = "since you are reading this it means you have been hacked"
        $a2 = "encrypting all your systems"
        $a3 = "Here's what you shouldn't do"
        $a4 = "Do not try to decrypt the files yourself"
        $a5 = "do not change the file extension yourself"
        $a6 = "Keep us for fools"
        $a7 = "Here's what you should do right after reading it"
        $a8 = "send our message to the CEO of the company, as well as to the IT department"
        $a9 = "you should contact us within 24 hours by email"
        $a10 = "As a guarantee that we can decrypt the files, we suggest that you send several files for free decryption"
        $a11 = "Mails to contact us"

    condition:
        filesize < 5KB and
        8 of them
}

rule MAL_Trigona_strings {
    meta:
        description = "Matches strings found in Trigona ransomware samples."
        last_modified = "2024-03-28"
        author = "@petermstewart"
        DaysofYara = "88/100"
        sha256 = "fb128dbd4e945574a2795c2089340467fcf61bb3232cc0886df98d86ff328d1b"
        sha256 = "d743daa22fdf4313a10da027b034c603eda255be037cb45b28faea23114d3b8a"

    strings:
        $a1 = "how_to_decrypt" wide
        $b1 = "nolocal"
        $b2 = "nolan"
        $b3 = "shutdown"
        $b4 = "random_file_system"
        $b5 = "fullmode"
        $b6 = "erasemode"
        $b7 = "network_scan_finished"
        $b8 = "is_testing"

    condition:
        file_pe_header and
        $a1 and
        4 of ($b*)
}

rule MAL_Trigona_ransomnote {
    meta:
        description = "Matches strings found in Trigona ransom notes."
        last_modified = "2024-03-29"
        author = "@petermstewart"
        DaysofYara = "89/100"

    strings:
        $a1 = "3x55o3u2b7cjs54eifja5m3ottxntlubhjzt6k6htp5nrocjmsxxh7ad.onion"
        $b1 = "<title>ENCRYPTED</title>"
        $b2 = "the entire network is encrypted"
        $b3 = "your business is losing money"
        $b4 = "All documents, databases, backups and other critical data were encrypted and leaked"
        $b5 = "The program uses a secure AES algorithm"
        $b6 = "decryption impossible without contacting us"
        $b7 = "To recover your data, please follow the instructions"
        $b8 = "Download Tor Browser"
        $b9 = "Open decryption page"
        $b10 = "Auth using this key"

    condition:
        filesize < 20KB and
        7 of them
}

rule MAL_HuntersInternational_Win_strings {
    meta:
        description = "Matches strings found in Hunters International Windows ransomware samples."
        last_modified = "2024-03-30"
        author = "@petermstewart"
        DaysofYara = "90/100"
        sha256 = "c4d39db132b92514085fe269db90511484b7abe4620286f6b0a30aa475f64c3e"

    strings:
        $a1 = "windows_encrypt/src/main.rs"
        $a2 = "skipped, reserve dir"
        $a3 = "skipped, min size:"
        $a4 = "skipped, symlink:"
        $a5 = "skipped, reserved file:"
        $a6 = "skipped, reserved extension:"
        $a7 = "got, dir:"
        $a8 = "encrypting"

    condition:
        file_pe_header and
        all of them
}

rule MAL_HuntersInternational_ransomnote {
    meta:
        description = "Matches strings found in Hunters International ransom notes."
        last_modified = "2024-03-31"
        author = "@petermstewart"
        DaysofYara = "91/100"

    strings:
        $a1 = "_   _ _   _ _   _ _____ _____ ____  ____"
        $a2 = "| | | | | | | \\ | |_   _| ____|  _ \\/ ___|"
        $a3 = "| |_| | | | |  \\| | | | |  _| | |_) \\___ \\"
        $a4 = "|  _  | |_| | |\\  | | | | |___|  _ < ___) |"
        $a5 = "|_|_|_|\\___/|_|_\\_|_|_|_|_____|_|_\\_\\____/____ ___ ___  _   _    _    _"
        $a6 = "|_ _| \\ | |_   _| ____|  _ \\| \\ | |  / \\|_   _|_ _/ _ \\| \\ | |  / \\  | |"
        $a7 = "| ||  \\| | | | |  _| | |_) |  \\| | / _ \\ | |  | | | | |  \\| | / _ \\ | |"
        $a8 = "| || |\\  | | | | |___|  _ <| |\\  |/ ___ \\| |  | | |_| | |\\  |/ ___ \\| |___"
        $a9 = "|___|_| \\_| |_| |_____|_| \\_\\_| \\_/_/   \\_\\_| |___\\___/|_| \\_/_/   \\_\\_____|"
        $b1 = "hunters33mmcwww7ek7q5ndahul6nmzmrsumfs6aenicbqon6mxfiqyd.onion"
        $b2 = "hunters33dootzzwybhxyh6xnmumopeoza6u4hkontdqu7awnhmix7ad.onion"
        $b3 = "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion"
        $b4 = "hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd.onion"

    condition:
        filesize < 5KB and
        all of ($a*) and
        1 of ($b*)
}

rule HUNT_HuntersInternational_ascii_art {
    meta:
        description = "Matches ascii art found in Hunters International ransomware notes."
        last_modified = "2024-03-31"
        author = "@petermstewart"
        DaysofYara = "91/100"

    strings:
        $a1 = "_   _ _   _ _   _ _____ _____ ____  ____"
        $a2 = "| | | | | | | \\ | |_   _| ____|  _ \\/ ___|"
        $a3 = "| |_| | | | |  \\| | | | |  _| | |_) \\___ \\"
        $a4 = "|  _  | |_| | |\\  | | | | |___|  _ < ___) |"
        $a5 = "|_|_|_|\\___/|_|_\\_|_|_|_|_____|_|_\\_\\____/____ ___ ___  _   _    _    _"
        $a6 = "|_ _| \\ | |_   _| ____|  _ \\| \\ | |  / \\|_   _|_ _/ _ \\| \\ | |  / \\  | |"
        $a7 = "| ||  \\| | | | |  _| | |_) |  \\| | / _ \\ | |  | | | | |  \\| | / _ \\ | |"
        $a8 = "| || |\\  | | | | |___|  _ <| |\\  |/ ___ \\| |  | | |_| | |\\  |/ ___ \\| |___"
        $a9 = "|___|_| \\_| |_| |_____|_| \\_\\_| \\_/_/   \\_\\_| |___\\___/|_| \\_/_/   \\_\\_____|"

    condition:
        all of them
}

rule MAL_FIN13_BLUEAGAVE_PowerShell {
    meta:
        description = "Matches code sample of BLUEAGAVE PowerShell webshell used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-01"
        author = "@petermstewart"
        DaysofYara = "92/100"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "$decode = [System.Web.HttpUtility]::UrlDecode($data.item('kmd'))" ascii wide
        $a2 = "$Out =  cmd.exe /c $decode 2>&1" ascii wide
        $a3 = "$url = 'http://*:" ascii wide

    condition:
        filesize < 5KB and
        all of them
}

rule MAL_FIN13_BLUEAGAVE_Perl {
    meta:
        description = "Matches strings found in BLUEAGAVE Perl webshell used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-02"
        author = "@petermstewart"
        DaysofYara = "93/100"
        ref = "https://www.netwitness.com/wp-content/uploads/FIN13-Elephant-Beetle-NetWitness.pdf"

    strings:
        $a1 = "'[cpuset]';" ascii wide
        $a2 = "$key == \"kmd\"" ascii wide
        $a3 = "SOMAXCONN,"
        $a4 = "(/\\s*(\\w+)\\s*([^\\s]+)\\s*HTTP\\/(\\d.\\d)/)" ascii wide
        $a5 = "s/^\\s+//; s/\\s+$//;" ascii wide

    condition:
        filesize < 5KB and
        all of them
}

rule MAL_FIN13_LATCHKEY {
    meta:
        description = "Matches strings found in LATCHKEY ps2exe loader used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-03"
        author = "@petermstewart"
        DaysofYara = "94/100"
        sha256 = "b23621caf5323e2207d8fbf5bee0a9bd9ce110af64b8f5579a80f2767564f917"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "Unhandeled exception in PS2EXE" wide
        $b1 = "function Out-Minidump" base64wide
        $b2 = "$MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)" base64wide
        $b3 = "Get-Process lsass | Out-Minidump" base64wide

    condition:
        filesize < 50KB and
        file_pe_header and
        all of them
}

rule MAL_FIN13_PORTHOLE {
    meta:
        description = "Matches strings found in PORTHOLE Java network scanner used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-04"
        author = "@petermstewart"
        DaysofYara = "95/100"
        sha256 = "84ac021af9675763af11c955f294db98aeeb08afeacd17e71fb33d8d185feed5"
        sha256 = "61257b4ef15e20aa9407592e25a513ffde7aba2f323c2a47afbc3e588fc5fcaf"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "IpExtender.class"
        $a2 = "PortScanner.class"
        $a3 = "ObserverNotifier.class"

    condition:
        filesize < 20KB and
        file_zip and
        all of them
}

rule MAL_FIN13_CLOSEWATCH {
    meta:
        description = "Matches strings found in CLOSEWATCH JSP webshell and scanner used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-05"
        author = "@petermstewart"
        DaysofYara = "96/100"
        sha256 = "e9e25584475ebf08957886725ebc99a2b85af7a992b6c6ae352c94e8d9c79101"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "host=\"localhost\";"
        $a2 = "pport=16998;"
        $b1 = "request.getParameter(\"psh3\")"
        $b2 = "request.getParameter(\"psh\")"
        $b3 = "request.getParameter(\"psh2\")"
        $b4 = "request.getParameter(\"c\")"
        $c1 = "ja!, perra xD"

    condition:
        filesize < 20KB and
        6 of them
}

rule MAL_FIN13_NIGHTJAR {
    meta:
        description = "Matches strings found in NIGHTJAR file upload tool used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-06"
        author = "@petermstewart"
        DaysofYara = "97/100"
        sha256 = "5ece301c0e0295b511f4def643bf6c01129803bac52b032bb19d1e91c679cacb"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class"
        $a2 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.class"
        $a3 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.class"
        $a4 = "FileTransferClient.class"

    condition:
        filesize < 15KB and
        file_zip and
        all of them
}

rule MAL_FIN13_SIXPACK {
    meta:
        description = "Matches strings found in SIXPACK ASPX webshell/tunneler used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-07"
        author = "@petermstewart"
        DaysofYara = "98/100"
        sha256 = "a3676562571f48c269027a069ecb08ee08973b7017f4965fa36a8fa34a18134e"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "Sending a packs..."
        $a2 = "Sending a pack..."
        $b1 = "nvc[\"host\"]"
        $b2 = "nvc[\"port\"]"
        $b3 = "nvc[\"timeout\"]"

    condition:
        filesize < 15KB and
        1 of ($a*) and
        all of ($b*)
}

rule MAL_FIN13_SWEARJAR {
    meta:
        description = "Matches strings found in SWEARJAR cross-platform backdoor used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-08"
        author = "@petermstewart"
        DaysofYara = "99/100"
        sha256 = "e76e0a692be03fdc5b12483b7e1bd6abd46ad88167cd6b6a88f6185ed58c8841"
        sha256 = "2f23224937ac723f58e4036eaf1ee766b95ebcbe5b6a27633b5c0efcd314ce36"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class"
        $a2 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.class"
        $a3 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.class"
        $a4 = "bankcard.class"

    condition:
        filesize < 20KB and
        file_zip and
        all of them
}

rule MAL_FIN13_MAILSLOT {
    meta:
        description = "Matches strings found in MAILSLOT SMTP/POP C2 used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-09"
        author = "@petermstewart"
        DaysofYara = "100/100"
        sha256 = "5e59b103bccf5cad21dde116c71e4261f26c2f02ed1af35c0a17218b4423a638"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "%ws%\\uhost.exe" wide
        $a2 = "reg add %ws /v Uhost /t REG_SZ /d \"%ws\" /f" wide
        $a3 = "netsh advfirewall firewall add rule name=\"Uhost\"" wide
        $a4 = "profile=domain,private,public protocol=any enable=yes DIR=Out program=\"%ws\" Action=Allow" wide
        $b1 = "name=\"smime.p7s\"%s"
        $b2 = "Content-Transfer-Encoding: base64%s"
        $b3 = "Content-Disposition: attachment;"
        $b4 = "Content-Type: %smime;"

    condition:
        file_pe_header and
        all of them
}

rule leaked_anydesk_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "AnyDesk Revoked Certificates after public statement: https://anydesk.com/en/public-statement"
      references = "https://github.com/Neo23x0/signature-base/blob/master/yara/gen_anydesk_compromised_cert_feb23.yar"
      date = "07-02-2024"
      author = "Florian Roth"
      
   condition:
      uint16(0) == 0x5a4d and pe.timestamp > 1706486400 and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"
      )
}

rule malicious_hacking_team_malicious_certificate {
   meta:
      status = "expired"
      source = "malicious"
      description = "Certificate utilised by Hacking Team."
      references = "https://www.trendmicro.com/vinfo/fr/security/news/vulnerabilities-and-exploits/the-hacking-team-leak-zero-days-patches-and-more-zero-days"
      date = "15-11-2023"
      author = "WithSecure"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and
         pe.signatures[i].serial == "0f:1b:43:48:4a:13:69:c8:30:38:dc:24:e7:77:8b:7d"
      )
}

rule leaked_hangil_it_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "Leaked Hangil IT Co., Ltd certificate utilised by various malware."
      references = ""
      date = "15-11-2023"
      author = "Riccardo Ancarani"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "Sectigo Public Code Signing CA R36" and
         pe.signatures[i].serial == "01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45"
      )
}

rule malicious_lamera_dprk_certificate {
   meta:
      status = "revoked"
      source = "malicious"
      description = "Certificate utilised to sign malware attributed to North Korea."
      references = "https://labs.withsecure.com/publications/no-pineapple-dprk-targeting-of-medical-research-and-technology-sector"
      date = "31-08-2023"
      author = "WithSecure"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "LAMERA CORPORATION LIMITED" and
         pe.signatures[i].serial == "87:9f:a9:42:f9:f0:97:b7:4f:d6:f7:da:bc:f1:74:5a"
      )
}

rule leaked_lapsus_nvidia_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "Leaked NVIDIA certificate utilised by LAPSUS."
      references = "https://www.malwarebytes.com/blog/news/2022/03/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do"
      date = "31-08-2023"
      author = "Florian Roth"
      
   condition:
      uint16(0) == 0x5a4d and pe.timestamp > 1646092800 and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and
         pe.signatures[i].serial == "43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"
      )
}

rule Logger_Macho_EntryPoint_LCMain
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from LCMain / MAIN_DYLIB load commands"
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	for any LCMain in (0 .. 0x1000) : (
            	uint32be(LCMain) == 0x28000080 and console.log("LCMain_entry_point_hash: ", hash.md5(uint32(LCMain+8), 16))
        )
}

rule Logger_Macho_EntryPoint_UnixThread_32Bit
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from UnixThread load commands"
    condition:
        uint32be(0x0) == 0xCEFAEDFE and
		for any unix_Thread in (0 .. 0x1000) : (
                	uint32be(unix_Thread) == 0x05000000 and
			uint32be(unix_Thread+8) == 0x01000000
			and console.hex("unix_Thread_x32_entry_point_hash: ", uint32(unix_Thread+0x38))
        )
}

rule Logger_Macho_EntryPoint_UnixThread_64Bit
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from UnixThread load commands"
    condition:
        uint32be(0x0) == 0xCFFAEDFE
		and for any unix_Thread in (0 .. 0x1000) : (
                	uint32be(unix_Thread) == 0x05000000 and
			uint32be(unix_Thread+8) == 0x04000000
			and console.hex("unix_Thread_entry_point_64: ", (uint32(unix_Thread+0x90)) + 0x100000000)
                )
}

rule macho_cstring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' cstring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__cstring" and
				math.entropy(sect.offset, sect.size) >= 7 and
				console.log("__cstring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_cfstring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' cfstring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__cfstring" and
				math.entropy(sect.offset, sect.size) >= 7 and
				console.log("__cfstring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_ustring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' ustring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__ustring" and
				math.entropy(sect.offset, sect.size) >= 4.5 and
				console.log("__ustring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_libframework_suspicious {
  meta:
    description = "Detects on LightSpy variant dylibs"
    author = "Jacob Latonis @jacoblatonis"
    date = "2024-04-25"

  condition:
    macho.has_dylib("/usr/lib/libsqlite3.dylib") and macho.has_dylib("/usr/local/lib/libframework.dylib")
}

rule macho_no_section_text
{
	meta:
		description = "Identify macho executable without a __text section."
		author = "@shellcromancer"
		version = "1.1"
		date = "2023.02.11"
		sample = "b117f042fe9bac7c7d39eab98891c2465ef45612f5355beea8d3c4ebd0665b45"
		sample = "e94781e3da02c7f1426fd23cbd0a375cceac8766fe79c8bc4d4458d6fe64697c"
		DaysofYARA = "42/100"
		DaysofYARA = "43/100"

	condition:
		macho.filetype == macho.MH_EXECUTE and
		not for any file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__TEXT" and
				for any sect in seg.sections : (
					sect.sectname == "__text"
				)
			)
		) and
		not for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__text"
			)
		)
}


/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/
rule macho_no_pagezero
{
	meta:
		description = "Identify macho executable without a __PAGEZERO segment."
		author = "@shellcromancer"
		version = "1.1"
		date = "2023.02.09"
		sample = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197" // FinSpy
		DaysofYARA = "40/100"
		DaysofYARA = "43/100"

	condition:
		macho.filetype == macho.MH_EXECUTE and
		not for any file in macho.file : (
			not for any seg in file.segments : (
				seg.segname == "__PAGEZERO"
			)
		) and
		not for any seg in macho.segments : (
			seg.segname == "__PAGEZERO"
		)
}

rule macho_has_restrict
{
	meta:
		description = "Identify macho executables with a __RESTRICT/__restrict section."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.08"
		reference = "https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/common/MachOFile.cpp#L1588-L1598"
		sample = "fa82c3ea06d0a6da0167632d31a9b04c0569f00b4c80f921f004ceb9b7e43a7c"
		DaysofYARA = "39/100"

	condition:
		// check for section in Universal/FAT binaries
		for all file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__RESTRICT" and
				for any sect in seg.sections : (
					sect.sectname == "__restrict"
				)
			)
		) or
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__RESTRICT" and
			for any sect in seg.sections : (
				sect.sectname == "__restrict"
			)
		)
}

rule macho_text_protected
{
	meta:
		description = "Identify macho executables with the __TEXT segment marked as protected."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.10"
		reference = "https://objective-see.org/blog/blog_0x0D.html"
		reference = "https://ntcore.com/?p=436"
		sample = "58e4e4853c6cfbb43afd49e5238046596ee5b78eca439c7d76bd95a34115a273"
		DaysofYARA = "41/100"

	condition:
		// check for segment protection in Universal/FAT binaries
		for any file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__TEXT" and
				seg.flags & macho.SG_PROTECTED_VERSION_1
			)
		) or
		// check for segment protection in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			seg.flags & macho.SG_PROTECTED_VERSION_1
		)
}
rule macos_bundle_qlgenerator
{
	meta:
		description = "Identify macOS QuickLook plugins - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.15"
		reference = "https://theevilbit.github.io/beyond/beyond_0012/"
		DaysofYARA = "46/100"

	strings:
		$factory = "QuickLookGeneratorPluginFactory"

	condition:
		$factory and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_mdimporter
{
	meta:
		description = "Identify macOS Spotlight Importers - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.16"
		reference = "https://theevilbit.github.io/beyond/beyond_0011/"
		DaysofYARA = "47/100"

	strings:
		$factory = "MetadataImporterPluginFactory"

	condition:
		$factory and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_saver
{
	meta:
		description = "Identify macOS Screen Savers - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.17"
		reference = "https://theevilbit.github.io/beyond/beyond_0016/"
		reference = "https://posts.specterops.io/saving-your-access-d562bf5bf90b"
		DaysofYARA = "48/100"

	strings:
		$init1 = "initWithFrame"
		$init2 = "configureSheet"
		$init3 = "hasConfigureSheet"
		$init4 = "startAnimation"

	condition:
		3 of them and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_colorpicker
{
	meta:
		description = "Identify macOS Color Picker's - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.18"
		reference = "https://theevilbit.github.io/beyond/beyond_0017/"
		DaysofYARA = "49/100"

	strings:
		$init1 = "NSColorPicker"
		$init2 = "NSColorPickingCustom"

	condition:
		all of them and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

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
rule MAL_Lckmac_strings {
    meta:
        description = "Matches function name strings found in MachO ransomware sample uploaded to VirusTotal with filename 'lckmac'."
        last_modified = "2024-03-16"
        author = "@petermstewart"
        DaysofYara = "76/100"
        sha256 = "e02b3309c0b6a774a4d940369633e395b4c374dc3e6aaa64410cc33b0dcd67ac"
        ref = "https://x.com/malwrhunterteam/status/1745144586727526500"

    strings:
        $a1 = "main.parsePublicKey"
        $a2 = "main.writeKeyToFile"
        $a3 = "main.getSystemInfo"
        $a4 = "main.EncryptTargetedFiles"
        $a5 = "main.shouldEncryptFile"
        $a6 = "main.encryptFile"
        $a7 = "main.deleteSelf"

    condition:
        (uint32(0) == 0xfeedface or     //MH_MAGIC
        uint32(0) == 0xcefaedfe or      //MH_CIGAM
        uint32(0) == 0xfeedfacf or      //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or      //MH_CIGAM_64
        uint32(0) == 0xcafebabe or      //FAT_MAGIC
        uint32(0) == 0xbebafeca) and    //FAT_CIGAM
        all of them
}
rule leaked_msi_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "Leaked certificate from MicroStar International (MSI) driver package."
      references = "https://thehackernews.com/2023/05/msi-data-breach-private-code-signing.html"
      date = "31-08-2023"
      author = "WithSecure"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         pe.signatures[i].serial == "0b:88:60:32:86:1d:95:53:c6:8f:80:33:13:a9:89:75"
      )
}

rule SI_APT_Kimsuky_Certificate_D2Innovation_bc3a_Jan24 {
    meta:
        version = "1.0"
        date = "2024-01-09"
        modified = "2024-01-09"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects PE executables signed by D2innovation Co.,LTD. Malicious use of this cert is attributed to the Kimsuky APT"
        category = "INFO"
        mitre_att = "T1588.003"
        actor_type = "APT"
        actor = "Kimsuky"
        reference = "https://twitter.com/asdasd13asbz/status/1744279858778456325"
        hash = "2e0ffaab995f22b7684052e53b8c64b9283b5e81503b88664785fe6d6569a55e"
        hash = "f8ab78e1db3a3cc3793f7680a90dc1d8ce087226ef59950b7acd6bb1beffd6e3"
        hash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"
        hash = "ff3718ae6bd59ad479e375c602a81811718dfb2669c2d1de497f02baf7b4adca"
        hash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"
        minimum_yara = "4.2"
        best_before = "2025-01-09"

    condition:
        uint16(0) == 0x5A4D
        and pe.number_of_signatures > 0
        //and pe.timestamp > 1701385200
        and for any i in (0 .. pe.number_of_signatures): (
            pe.signatures[i].issuer contains "Sectigo Public Code Signing CA R36" 
            and pe.signatures[i].serial == "00:88:90:ca:b1:cd:51:0c:d2:0d:ab:4c:e5:94:8c:bc:3a")
}rule SI_APT_unattrib_netdoor_Jan24 {
    meta:
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-01-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects the 'netdoor' .NET TCP reverse shell (CMD/Powershell)."
        category = "MALWARE"
        malware_type = "Reverse Shell"
        mitre_att = "T1059"
        actor_type = "APT"
        reference = "https://twitter.com/h2jazi/status/1747334436805341283"
        hash = "8920021af359df74892a2b86da62679c444362320f7603f43c2bd9217d3cb333"
        hash = "7581b86dd1d85593986f1dd34942d007699d065f2407c27683729fa9a32ae1d6"
        hash = "c914343ac4fa6395f13a885f4cbf207c4f20ce39415b81fd7cfacd0bea0fe093"
        minimum_yara = "2.0.0"
        best_before = "2025-01-18"

    strings:
        $w_1 = "Attempting to reconnect in {0} seconds..." wide
        $w_2 = "Error receiving/processing commands:" wide
        $w_3 = "Connection lost. Reconnecting..." wide
        $w_4 = "Exiting the application." wide
        $w_5 = "Server disconnected." wide
        $w_6 = "ServerIP" wide
        $w_7 = "powershell" wide
        $w_8 = "cmd.exe" wide

        $a_1 = "ConnectAndExecuteAsync" ascii
        $a_2 = "SendIdentificationDataAsync" ascii
        $a_3 = "ReceiveAndExecuteCommandsAsync" ascii
        $a_4 = "ProcessCommandsAsync" ascii
        $a_5 = "ExecuteCommandAsync" ascii
        $a_6 = "reconnectionAttempts" ascii

        $origFileName = /[0-9]{4}202[0-9]\.exe/

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100KB
        and 4 of ($w_*)
        and 4 of ($a_*)
        and #origFileName >= 0
}rule SI_CRYPT_hXOR_Jan24 : Crypter {

    meta:
        version = "1.0"
        date = "2024-01-04"
        modified = "2024-01-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects executables packed/encrypted with the hXOR-Packer open-source crypter."
        category = "TOOL"
        mitre_att = "T1027.002"
        actor_type = "CRIMEWARE"
        reference = "https://github.com/akuafif/hXOR-Packer"
        hash = "7712186f3e91573ea1bb0cc9f85d35915742b165f9e8ed3d3e795aa5e699230f"
        minimum_yara = "2.0.0"
        best_before = "2025-01-04"

    strings:
        //This rule has been validated for the compression, encryption and compression+encryption modes of hXOR

        //Signature to locate the payload
        $binSignature = {46 49 46 41} 

        //Strings likely to be removed in attempts to conceal crypter
        $s_1 = "hXOR Un-Packer by Afif, 2012"
        $s_2 = "C:\\Users\\sony\\Desktop\\Packer\\"
        $s_3 = "H:\\Libraries\\My Documents\\Dropbox\\Ngee Ann Poly\\Semester 5\\Packer"
        $s_4 = "Scanning for Sandboxie..."
        $s_5 = "Scanning for VMware..."
        $s_6 = "Executing from Memory >>>>"
        $s_7 = "Extracting >>>>"
        $s_8 = "Decompressing >>>>"
        $s_9 = "Decrypting >>>>"

        //Anti-Analysis
        $aa_1 = "SbieDll.dll"
        $aa_2 = "VMwareUser.exe"
        $aa_3 = "GetTickCount"
        $aa_4 = "CreateToolhelp32Snapshot"

    condition:
        uint16(0) == 0x5A4D
        and uint16(0x28) != 0x0000 //IMAGE_DOS_HEADER.e_res2[0] contains offset for payload
        and $binSignature in (200000..filesize)
        and for all of ($s_*): (# >= 0) //these strings are optional
        and 3 of ($aa_*)
}

rule SI_CRYPT_ScrubCrypt_BAT_Jan24 : Crypter {

    meta:
        version = "1.2"
        date = "2024-01-02"
        modified = "2024-01-03"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects obfuscated Batch files generated by the ScrubCrypt Crypter"
        category = "TOOL"
        mitre_att = "T1027.002"
        actor_type = "CRIMEWARE"
        reference = "https://perception-point.io/blog/the-rebranded-crypter-scrubcrypt/"
        hash = "b6f71c1b85564ed3f60f5c07c04dd6926a99bafae0661509e4cc996a7e565b36"
        minimum_yara = "4.2"
        best_before = "2025-01-03"

    strings:
        //the Batch files contain patterns like %#% to disrupt easy string detection
        $obfp1 = {25 23 25}
        $obfp2 = {25 3D 25}
        $obfp3 = {25 40 25}
      
        $s_echo = "@echo off"
        $s_exe = ".exe"
        $s_set = "set"
        $s_copy = "copy"

    condition:
        (uint16(0) == 0x3a3a or uint16(0) == 0x6540) //at the beginning of the file there is either a comment (::) followed by b64 or "@echo off"
        and 3 of ($s_*)
        and filesize > 32KB
        and filesize < 10MB
        and #obfp1 > 16
        and #obfp2 > 16
        and #obfp3 > 16
        and math.entropy(0, filesize) >= 6 //due to the stray character obfuscation and base64 contents Shannon entropy is ~6
}rule SI_MAL_qBitStealer_Jan24 {
    meta:
        version = "1.1"
        date = "2024-01-30"
        modified = "2024-01-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects the 'qBit Stealer' data exfiltration tool"
        category = "MALWARE"
        malware_type = "Stealer"
        mitre_att = "T1119"
        actor_type = "CRIMEWARE"
        reference = "https://cyble.com/blog/decoding-qbit-stealers-source-release-and-data-exfiltration-prowess/"
        hash = "874ac477ea85e1a813ed167f326713c26018d9b2d649099148de7f9e7a163b23"
        hash = "2787246491b1ef657737e217142ca216c876c7178febcfe05f0379b730aae0cc"
        hash = "dab36adf8e01db42efc4a2a4e2ffc5251c15b511a83dae943bfe3d661f2d80ae"
        minimum_yara = "2.0.0"

    strings:
        $qBit_1 = "qBit Stealer RaaS"
        $qBit_2 = "(qbit@hitler.rocks)"
        $qBit_3 = "TRIAL VERSION - 24 Hour Access"
        $qBit_4 = "Email us to Purchase!"
        
        $comp_1 = "qBitStealer.go"
        $comp_2 = "megaFunc.go"
        $comp_3 = "functions.go"
        $comp_4 = "internal.go"
        
        $dbg_1 = "[+] Loaded configJs"
        $dbg_2 = "[+] Logged into Mega..."
        $dbg_3 = "[+] Please wait, files are being uploaded... WORKING!"
        $dbg_4 = "[+] Clean up of Left over Archived files completed with no errors."
        $dbg_5 = "Stolen Folder Name:"
        $dbg_6 = "Targeted File Extensions:"
        
        $api_1 = "http://worldtimeapi.org/api/timezone/Etc/UTC"
        $api_2 = "https://g.api.mega.co.nz"

    condition:
        uint16(0) == 0x5a4d
        and 2 of ($qBit_*)
        and 3 of ($comp_*)
        and 4 of ($dbg_*)
        and all of ($api_*)
}

rule SUSP_Macho_Execution_BinBash
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like bash shell"

    strings:
        $ = "bin/bash" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_Execution_Bin_sh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like sh shell"

    strings:
        $ = "bin/sh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_Execution_BinZsh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like zsh shell"

    strings:
        $ = "bin/zsh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}


rule SUSP_Macho_Execution_Bin_tcsh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like tcsh shell"

    strings:
        $ = "bin/tcsh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_Execution_CHMOD
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like chmod to mark files as executable"

    strings:
        $ = "chmod + x" ascii wide
        $ = "chmod +x" ascii wide
        $ = "chmod+x" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and any of them
}

rule finspy0 : cdshide android
{

	meta:
		description = "Detect Gamma/FinFisher FinSpy for Android #GovWare"
		date = "2020/01/07"
		author = "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)"
		reference1 = "https://github.com/devio/FinSpy-Tools"
		reference2 = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference3 = "https://www.ccc.de/de/updates/2019/finspy"
		sample = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		$re and (#re > 50)
}
