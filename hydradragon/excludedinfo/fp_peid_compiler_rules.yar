import "pe"

// Extracted 100% False Positive Rules (Compilers, Installers, Media formats, Game DRM)
// Sourced from PEiD signatures with 'at pe.entry_point'

// ===== removed from hydradragon\yara-x\rules\clean_rules.yar (20261003_200100) =====
rule WiseInstallerStub {
  strings:
    $a0 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
    $a1 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 }
    $a2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2
}

rule PseudoSigner01MicrosoftVisualBasic60DLLAnorganix {
  strings:
    $a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

  condition:
    $a0 at (pe.entry_point)
}

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCx {
  strings:
    $a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

  condition:
    $a0 at (pe.entry_point)
}

rule UPXFreakv01BorlandDelphiHMX0101 {
  strings:
    $a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
    $a1 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point)
}

rule PseudoSigner02BorlandC1999Anorganix {
  strings:
    $a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02LCCWin321xAnorganix {
  strings:
    $a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }

  condition:
    $a0 at (pe.entry_point)
}

rule FSGv110EngdulekxtBorlandC {
  strings:
    $a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
    $a1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point)
}

rule FSGv110EngdulekxtMASM32TASM32 {
  strings:
    $a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
    $a1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point)
}

rule FSGv110EngdulekxtBorlandDelphiBorlandC {
  strings:
    $a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
    $a1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
    $a2 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
}

rule VideoLanClient {
  strings:
    $a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02MinGWGCC2xAnorganix {
  strings:
    $a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

  condition:
    $a0 at (pe.entry_point)
}

rule InnoSetupModule {
  strings:
    $a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
    $a1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }

  condition:
    $a0 at (pe.entry_point) or $a1
}

rule PseudoSigner02MicrosoftVisualBasic5060Anorganix {
  strings:
    $a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02VideoLanClientAnorganix {
  strings:
    $a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }

  condition:
    $a0 at (pe.entry_point)
}

rule WiseInstallerStubv11010291 {
  strings:
    $a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02REALBasicAnorganix {
  strings:
    $a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

  condition:
    $a0 at (pe.entry_point)
}

rule MSLRHv032afakeMSVC70DLLMethod3emadicius {
  strings:
    $a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02BorlandCDLLMethod2Anorganix {
  strings:
    $a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02LCCWin32DLLAnorganix {
  strings:
    $a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

  condition:
    $a0 at (pe.entry_point)
}

rule PseudoSigner02WATCOMCCEXEAnorganix {
  strings:
    $a0 = { E9 00 00 00 00 90 90 90 90 57 41 }

  condition:
    $a0 at (pe.entry_point)
}

rule NullsoftInstallSystemv1xx {
  strings:
    $a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
    $a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point)
}


rule _Ding_Boys_PElock_Phantasm_v08_ {
  meta:
    description = "Ding Boy's PE-lock Phantasm v0.8"

  strings:
    $0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_v198_ {
  meta:
    description = "Nullsoft Install System v1.98"

  strings:
    $0 = { 83 EC 0C 53 55 56 57 FF 15 70 40 ?? 8B 35 92 40 ?? 05 E8 03 ?? ?? 89 44 24 14 B3 20 FF 15 2C 70 40 ?? BF ?? 04 ?? ?? 68 ?? 57 FF 15 40 ?? 57 FF }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_v1xx_ {
  meta:
    description = "Nullsoft Install System v1.xx"

  strings:
    $0 = { 83 EC 0C 53 56 57 FF 15 20 71 40 ?? 05 E8 03 ?? ?? BE 60 FD 41 ?? 89 44 24 10 B3 20 FF 15 28 70 40 ?? 68 ?? 04 ?? ?? FF 15 28 71 40 ?? 50 56 FF 15 08 71 40 ?? 80 3D 60 FD 41 ?? 22 75 08 80 }
    $1 = { 83 EC 0C 53 56 57 FF 15 2C 81 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Wise_Installer_Stub_ {
  meta:
    description = "Wise Installer Stub"

  strings:
    $0 = { 55 8B EC 81 EC 78 05 ?? ?? 53 56 BE 04 01 ?? ?? 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 ?? 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 ?? 8B 3D 2C 20 40 ?? 53 53 }
    $1 = { 55 8B EC 81 EC 40 0F ?? ?? 53 56 57 6A 04 FF 15 F4 30 40 ?? FF 15 74 30 40 ?? 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Inno_Setup_Module_ {
  meta:
    description = "Inno Setup Module"

  strings:
    $0 = "Inn"
    $1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Inno_Setup_Module_v109a_ {
  meta:
    description = "Inno Setup Module v1.09a"

  strings:
    $0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 }

  condition:
    $0 at pe.entry_point
}

rule _Wise_Installer_Stub_v11010291_ {
  meta:
    description = "Wise Installer Stub v1.10.1029.1"

  strings:
    $0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PIMP_Install_System_v1x_ {
  meta:
    description = "Nullsoft PIMP Install System v1.x"

  strings:
    $0 = { FF 60 FF CA FF ?? BA DC 0D E0 40 ?? 50 ?? 60 ?? 70 ?? }

  condition:
    $0 at pe.entry_point
}

rule _UPX_v0896__v102__v105__v122_Delphi_stub_ {
  meta:
    description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 (Delphi) stub"

  strings:
    $0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 }

  condition:
    $0 at pe.entry_point
}

rule _Inno_Setup_Module_v129_ {
  meta:
    description = "Inno Setup Module v1.2.9"

  strings:
    $0 = { 55 8B EC 81 EC 14 ?? ?? 53 56 57 6A ?? FF 15 68 FF 15 85 C0 74 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_v20b2_v20b3_ {
  meta:
    description = "Nullsoft Install System v2.0b2, v2.0b3"

  strings:
    $0 = { 55 8B EC 81 EC ?? ?? 56 57 6A BE 59 8D }

  condition:
    $0 at pe.entry_point
}

rule _Ding_Boys_PElock_Phantasm_v15b3_ {
  meta:
    description = "Ding Boy's PE-lock Phantasm v1.5b3"

  strings:
    $0 = { 9C 55 57 56 52 51 53 9C FA E8 5D 81 ED 5B 53 40 B0 E8 5E 83 C6 11 B9 27 30 06 46 49 75 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PIMP_Install_System_v13x_ {
  meta:
    description = "Nullsoft PIMP Install System v1.3x"

  strings:
    $0 = { 83 EC 5C 53 55 56 57 FF }

  condition:
    $0 at pe.entry_point
}

rule _Ding_Boys_PElock_Phantasm_v10__v11_ {
  meta:
    description = "Ding Boy's PE-lock Phantasm v1.0 / v1.1"

  strings:
    $0 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? }

  condition:
    $0 at pe.entry_point
}

rule _UPX_290_LZMA_Delphi_stub__Markus_Oberhumer_Laszlo_Molnar__John_Reiser_ {
  meta:
    description = "UPX 2.90 [LZMA] (Delphi stub) -> Markus Oberhumer, Laszlo Molnar & John Reiser"

  strings:
    $0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }

  condition:
    $0 at pe.entry_point
}

rule _PureBasic_4x_DLL__Neil_Hodgson_ {
  meta:
    description = "PureBasic 4.x DLL -> Neil Hodgson"

  strings:
    $0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

  condition:
    $0 at pe.entry_point
}

rule _MASM32_ {
  meta:
    description = "MASM32"

  strings:
    $0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)"

  strings:
    $0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
    $1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _PseudoSigner_02_Borland_Delphi_DLL__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Borland Delphi DLL] --> Anorganix"

  strings:
    $0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp__ASM_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++ / ASM)"

  strings:
    $0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

  condition:
    $0 at pe.entry_point
}

rule _PureBasic_DLL__Neil_Hodgson_ {
  meta:
    description = "PureBasic DLL -> Neil Hodgson"

  strings:
    $0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Borland_Delphi_50_KOLMCK__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [Borland Delphi 5.0 KOL/MCK] --> Anorganix"

  strings:
    $0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_MinGW_GCC_2x__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [MinGW GCC 2.x] --> Anorganix"

  strings:
    $0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_LCC_Win32_DLL__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [LCC Win32 DLL] --> Anorganix"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_Microsoft_Visual_Basic_50__60__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Microsoft Visual Basic 5.0 - 6.0] --> Anorganix"

  strings:
    $0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _NSIS_Installer__NullSoft_ {
  meta:
    description = "NSIS Installer --> NullSoft"

  strings:
    $0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_VideoLanClient__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Video-Lan-Client] --> Anorganix"

  strings:
    $0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Basic_50__60_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Basic 5.0 / 6.0)"

  strings:
    $0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_WATCOM_CCpp_EXE__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [WATCOM C/C++ EXE] --> Anorganix"

  strings:
    $0 = { E9 00 00 00 00 90 90 90 90 57 41 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_MinGW_GCC_2x__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [MinGW GCC 2.x] --> Anorganix"

  strings:
    $0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Borland_Delphi_60__70__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [Borland Delphi 6.0 - 7.0] --> Anorganix"

  strings:
    $0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Borland_Cpp_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)"

  strings:
    $0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
    $1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
    $2 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi_20_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi 2.0)"

  strings:
    $0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_LCC_Win32_1x__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [LCC Win32 1.x] --> Anorganix"

  strings:
    $0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v120_Eng__dulekxt__Borland_Cpp_ {
  meta:
    description = "FSG v1.20 (Eng) -> dulek/xt -> (Borland C++)"

  strings:
    $0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_Borland_Delphi_Setup_Module__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Borland Delphi Setup Module] --> Anorganix"

  strings:
    $0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Basic__MASM32_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Basic / MASM32)"

  strings:
    $0 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Cpp_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland C++)"

  strings:
    $0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
    $1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _UPXFreak_v01_Borland_Delphi__HMX0101_ {
  meta:
    description = "UPXFreak v0.1 (Borland Delphi) -> HMX0101"

  strings:
    $0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
    $1 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _VideoLanClient_ {
  meta:
    description = "Video-Lan-Client"

  strings:
    $0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_LCC_Win32_1x__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [LCC Win32 1.x] --> Anorganix"

  strings:
    $0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v120_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp_ {
  meta:
    description = "FSG v1.20 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)"

  strings:
    $0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_REALBasic__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [REALBasic] --> Anorganix"

  strings:
    $0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_Borland_Cpp_DLL_Method_2__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Borland C++ DLL (Method 2)] --> Anorganix"

  strings:
    $0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_4x__LCC_Win32_1x_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 4.x / LCC Win32 1.x)"

  strings:
    $0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_VideoLanClient__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [Video-Lan-Client] --> Anorganix"

  strings:
    $0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Cpp_1999_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland C++ 1999)"

  strings:
    $0 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__MASM32_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32)"

  strings:
    $0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v120_Eng__dulekxt__MASM32__TASM32_ {
  meta:
    description = "FSG v1.20 (Eng) -> dulek/xt -> (MASM32 / TASM32)"

  strings:
    $0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_Borland_Cpp_1999__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Borland C++ 1999] --> Anorganix"

  strings:
    $0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Microsoft_Visual_Basic_50__60__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [Microsoft Visual Basic 5.0 - 6.0] --> Anorganix"

  strings:
    $0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_WATCOM_CCpp_EXE__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [WATCOM C/C++ EXE] --> Anorganix"

  strings:
    $0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

  condition:
    $0 at pe.entry_point
}

rule _MSLRH_v032a_fake_MSVCpp_DLL_Method_4__emadicius_ {
  meta:
    description = "[MSLRH] v0.32a (fake MSVC++ DLL Method 4) -> emadicius"

  strings:
    $0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_LCC_Win32_DLL__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [LCC Win32 DLL] --> Anorganix"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }

  condition:
    $0 at pe.entry_point
}

rule _PureBasic_4x__Neil_Hodgson_ {
  meta:
    description = "PureBasic 4.x -> Neil Hodgson"

  strings:
    $0 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v120_Eng__dulekxt__Borland_Delphi__Borland_Cpp_ {
  meta:
    description = "FSG v1.20 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)"

  strings:
    $0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_REALBasic__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [REALBasic] --> Anorganix"

  strings:
    $0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__MASM32__TASM32__Microsoft_Visual_Basic_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32 / Microsoft Visual Basic)"

  strings:
    $0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__MASM32__TASM32_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32)"

  strings:
    $0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
    $1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _PseudoSigner_01_Microsoft_Visual_Basic_60_DLL__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [Microsoft Visual Basic 6.0 DLL] --> Anorganix"

  strings:
    $0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_Watcom_CCpp_DLL__Anorganix_ {
  meta:
    description = "PseudoSigner 0.2 [Watcom C/C++ DLL] --> Anorganix"

  strings:
    $0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

  condition:
    $0 at pe.entry_point
}

rule _MSLRH_v032a_fake_MSVCpp_70_DLL_Method_3__emadicius_ {
  meta:
    description = "[MSLRH] v0.32a (fake MSVC++ 7.0 DLL Method 3) -> emadicius"

  strings:
    $0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _MSLRH_v032a_fake_MSVCpp_60_DLL__emadicius_ {
  meta:
    description = "[MSLRH] v0.32a (fake MSVC++ 6.0 DLL) -> emadicius"

  strings:
    $0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cppx_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)x"

  strings:
    $0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Borland_Delphi_30__Anorganix_ {
  meta:
    description = "PseudoSigner 0.1 [Borland Delphi 3.0] --> Anorganix"

  strings:
    $0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__bartxt__Watcom_CCpp_EXE_ {
  meta:
    description = "FSG v1.10 (Eng) -> bart/xt -> (Watcom C/C++ EXE)"

  strings:
    $0 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }

  condition:
    $0 at pe.entry_point
}

rule _AHTeam_EP_Protector_03_fake_Borland_Delphi_6070__FEUERRADER_ {
  meta:
    description = "AHTeam EP Protector 0.3 (fake Borland Delphi 6.0-7.0) -> FEUERRADER"

  strings:
    $0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }

  condition:
    $0 at pe.entry_point
}

rule _Jovian_VI_graphics_file_ {
  meta:
    description = "Jovian VI graphics file"

  strings:
    $0 = { 56 49 ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _RoboForm_Installer_ {
  meta:
    description = "RoboForm Installer"

  strings:
    $0 = { 55 8B EC 6A FF 68 E0 F3 40 00 68 44 90 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 68 F0 40 00 33 D2 8A D4 89 15 04 6B 41 00 8B C8 81 E1 FF 00 00 00 89 0D }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_1994_ {
  meta:
    description = "Borland C++ 1994"

  strings:
    $0 = { 8C CA 2E 89 ?? ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA A3 ?? ?? 8C }

  condition:
    $0 at pe.entry_point
}

rule _FSG_120_Eng__dulekxt__Borland_Cpp_ {
  meta:
    description = "FSG 1.20 (Eng) -> dulek/xt -> (Borland C++)"

  strings:
    $0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
    $1 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Scodl_Graphics_format_ {
  meta:
    description = "Scodl Graphics format"

  strings:
    $0 = { E0 01 ?? 00 ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Watcom_C_1995_ {
  meta:
    description = "Watcom C (1995)"

  strings:
    $0 = { FB B9 00 00 8E C1 26 BB 00 00 83 C3 0F 80 E3 F0 26 89 1E 00 00 26 8C 1E 00 00 01 E3 83 C3 0F 80 E3 F0 8E D1 89 DC 26 89 1E 00 00 89 DA D1 EA D1 EA D1 EA D1 EA 26 80 3E 00 00 00 75 3D 8B 0E 02 00 8C C0 29 C1 39 CA 72 0B BB 01 00 B8 00 00 8C }

  condition:
    $0 at pe.entry_point
}

rule _Lccwin_32_13_ {
  meta:
    description = "Lcc-win 32 1.3"

  strings:
    $0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 00 00 00 00 68 9A 10 40 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 }

  condition:
    $0 at pe.entry_point
}

rule _Histogram_graphics_file_ {
  meta:
    description = "Histogram graphics file"

  strings:
    $0 = { 6D 68 77 61 6E 68 00 04 01 02 01 02 }

  condition:
    $0 at pe.entry_point
}

rule _DrHalo_or_DrGenius_Palette_Graphics_format_ {
  meta:
    description = "DrHalo or DrGenius Palette Graphics format"

  strings:
    $0 = { 41 48 E3 00 00 00 0A 00 }

  condition:
    $0 at pe.entry_point
}

rule _HiJaak_Image_Draw_Graphics_format_ {
  meta:
    description = "HiJaak Image Draw Graphics format"

  strings:
    $0 = { 47 53 44 31 02 00 11 00 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_110_Eng__dulekxt__MASM32__TASM32_ {
  meta:
    description = "FSG 1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32)"

  strings:
    $0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }

  condition:
    $0 at pe.entry_point
}

rule _MSLRH_032a_fake_MSVCpp_DLL_Method_4__emadicius_ {
  meta:
    description = "MSLRH 0.32a (fake MSVC++ DLL Method 4) -> emadicius"

  strings:
    $0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 }

  condition:
    $0 at pe.entry_point
}

rule _CGM_Graphics_format_ {
  meta:
    description = "CGM Graphics format"

  strings:
    $0 = { 00 2A 08 48 69 4A 61 61 6B 20 32 }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_GCC_2x_ {
  meta:
    description = "MinGW GCC 2.x"

  strings:
    $0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Safedisc_V450000__Macrovision_Corporation__20080117_ {
  meta:
    description = "Safedisc V4.50.000 -> Macrovision Corporation * 20080117"

  strings:
    $0 = { 55 8B EC 60 BB 6E ?? ?? ?? B8 0D ?? ?? ?? 33 C9 8A 08 85 C9 74 0C B8 E4 ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 2B ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 D9 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 25 FC FF FF 83 C4 08 59 83 F8 00 74 }

  condition:
    $0 at pe.entry_point
}

rule _InterGraph_Graphics_format_ {
  meta:
    description = "InterGraph Graphics format"

  strings:
    $0 = { 08 09 FE 01 18 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _PNG_Graphics_format_ {
  meta:
    description = "PNG Graphics format"

  strings:
    $0 = { 89 50 4E 47 0D 0A 1A 0A }

  condition:
    $0 at pe.entry_point
}

rule _Inset_Systems_PIX_Graphics_format_ {
  meta:
    description = "Inset Systems PIX Graphics format"

  strings:
    $0 = { 03 00 ?? 00 00 00 20 00 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_v1xx__Nullsoft_ {
  meta:
    description = "Nullsoft Install System v1.xx -> Nullsoft"

  strings:
    $0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 80 40 00 68 00 04 00 00 FF 15 ?? 81 40 00 50 56 FF 15 ?? 81 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D F4 81 40 00 84 C0 74 19 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 }

  condition:
    $0 at pe.entry_point
}

rule _NextSun_Audio_file_ {
  meta:
    description = "Next/Sun Audio file"

  strings:
    $0 = ".snd"

  condition:
    $0 at pe.entry_point
}

rule _fasm__Tomasz_Grysztar_flat_ {
  meta:
    description = "fasm -> Tomasz Grysztar [flat"

  strings:
    $0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_GCC_DLL_2xx_ {
  meta:
    description = "MinGW GCC DLL 2.xx"

  strings:
    $0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Sharp_GPB_Graphics_format_ {
  meta:
    description = "Sharp GPB Graphics format"

  strings:
    $0 = { 4D 00 00 00 00 ?? ?? ?? ?? 08 00 00 00 03 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PiMP_Install_System_ {
  meta:
    description = "Nullsoft PiMP Install System"

  strings:
    $0 = { 83 EC ?? 53 55 56 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Graphics_Interface_Driver_ {
  meta:
    description = "Borland Graphics Interface Driver"

  strings:
    $0 = "FBGD"

  condition:
    $0 at pe.entry_point
}

rule _Reflexive_Arcade_Installer_ {
  meta:
    description = "Reflexive Arcade Installer"

  strings:
    $0 = { 55 8B EC 6A FF 68 98 48 42 00 68 B4 DC 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 31 42 00 33 D2 8A D4 89 15 8C CA 42 00 8B C8 81 E1 FF 00 00 00 89 0D }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_REALBasic_ {
  meta:
    description = "PseudoSigner 0.1 [REALBasic"

  strings:
    $0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }
    $1 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _SciFax_Graphics_file_ {
  meta:
    description = "SciFax Graphics file"

  strings:
    $0 = { 44 54 3D 00 }

  condition:
    $0 at pe.entry_point
}

rule _SMK_movie_file_ {
  meta:
    description = "SMK movie file"

  strings:
    $0 = "SMK2"

  condition:
    $0 at pe.entry_point
}

rule _setupexe_Section34data_ {
  meta:
    description = "setup.exe Section(3/4,.data)"

  strings:
    $0 = { 80 16 42 00 48 05 44 00 00 00 00 00 2E 3F 41 56 5F 63 6F 6D 5F 65 72 }

  condition:
    $0 at pe.entry_point
}

rule _Sun_Raster_Graphics_format_ {
  meta:
    description = "Sun Raster Graphics format"

  strings:
    $0 = { 59 A6 6A 95 }

  condition:
    $0 at pe.entry_point
}

rule _MingWin32_GCC_V3X_ {
  meta:
    description = "MingWin32 GCC V3.X"

  strings:
    $0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PIMP_Install_System_v13x___Nullsoft_ {
  meta:
    description = "Nullsoft PIMP Install System v1.3x ->  Nullsoft"

  strings:
    $0 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

  condition:
    $0 at pe.entry_point
}

rule _Delphi_v20_Unit_ {
  meta:
    description = "Delphi v2.0 Unit"

  strings:
    $0 = "DCU2"

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_20_ {
  meta:
    description = "Borland Delphi 2.0"

  strings:
    $0 = { E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_LCC_Win32_DLL_ {
  meta:
    description = "PseudoSigner 0.1 [LCC Win32 DLL"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }
    $1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Kofax_Group_4_graphics_file_ {
  meta:
    description = "Kofax Group 4 graphics file"

  strings:
    $0 = { 2E 4B 46 68 80 00 01 00 }

  condition:
    $0 at pe.entry_point
}

rule _Gem_VDI_Image_graphics_file_ {
  meta:
    description = "Gem VDI Image graphics file"

  strings:
    $0 = { 00 01 00 ?? 00 ?? 00 01 }

  condition:
    $0 at pe.entry_point
}

rule _MASMTASM_ {
  meta:
    description = "MASM/TASM"

  strings:
    $0 = { 6A 00 E8 ?? ?? 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _MSVCpp_v8_procedure_1_recognized__h_ {
  meta:
    description = "MSVC++ v.8 (procedure 1 recognized - h)"

  strings:
    $0 = { 55 8B EC 83 EC 10 A1 ?? ?? ?? ?? 83 65 F8 00 83 65 FC 00 53 57 BF 4E E6 40 BB 3B C7 BB 00 00 FF FF 74 0D 85 C3 74 09 F7 D0 A3 ?? ?? ?? ?? EB 60 56 8D 45 F8 50 FF 15 ?? ?? ?? ?? 8B 75 FC 33 75 F8 FF 15 ?? ?? ?? ?? 33 F0 FF 15 ?? ?? ?? ?? 33 F0 FF 15 ?? ?? ?? ?? 33 F0 8D 45 F0 50 FF 15 ?? ?? ?? ?? 8B 45 F4 33 45 F0 33 F0 3B F7 75 07 BE 4F E6 40 BB EB 0B 85 F3 75 07 8B C6 C1 E0 10 0B F0 89 35 ?? ?? ?? ?? F7 D6 89 35 ?? ?? ?? ?? 5E 5F 5B C9 C3 }

  condition:
    $0 at pe.entry_point
}

rule _OAZ_Fax_Graphics_format_ {
  meta:
    description = "OAZ Fax Graphics format"

  strings:
    $0 = { 0F 0F 0F 0F 01 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_v50_for_Windows_ {
  meta:
    description = "Borland C++ v5.0 for Windows"

  strings:
    $0 = { EB ?? 53 51 06 33 C0 50 9A ?? ?? ?? ?? 58 07 59 5B 9A }

  condition:
    $0 at pe.entry_point
}

rule _MSLRH_032a_fake_MSVCpp_70_DLL_Method_3__emadicius_ {
  meta:
    description = "MSLRH 0.32a (fake MSVC++ 7.0 DLL Method 3) -> emadicius"

  strings:
    $0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB }

  condition:
    $0 at pe.entry_point
}

rule _CAN2EXE_v001_ {
  meta:
    description = "CAN2EXE v0.01"

  strings:
    $0 = { 26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_50_KOLMCK_ {
  meta:
    description = "Borland Delphi 5.0 KOL/MCK"

  strings:
    $0 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _CorelDraw_CMX_Graphics_format_ {
  meta:
    description = "CorelDraw CMX Graphics format"

  strings:
    $0 = { 52 49 46 46 ?? ?? ?? ?? 43 4D 58 31 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_3_1_ {
  meta:
    description = "Borland Delphi 3 (1)"

  strings:
    $0 = { 55 8B EC 83 C4 F4 53 56 A1 0C CF 42 00 C6 00 01 B8 00 25 42 00 E8 00 00 FE FF BE 1C E1 42 00 A1 90 CE 42 00 E8 00 00 FE FF A1 CC CE 42 00 BA 00 00 42 00 E8 00 FD FE FF 84 C0 75 05 E8 00 02 FF FF E8 00 07 FF FF 33 C0 A3 14 E1 42 00 33 C0 A3 }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_runtime_system_1995_ {
  meta:
    description = "WATCOM C/C++ runtime system 1995"

  strings:
    $0 = { 53 56 57 55 8B 00 24 14 8B 00 24 18 8B 6C 24 1C 83 00 03 0F 87 00 01 00 00 89 00 2E FF 24 85 }

  condition:
    $0 at pe.entry_point
}

rule _QuickLink_II_Fax_Graphics_format_ {
  meta:
    description = "QuickLink II Fax Graphics format"

  strings:
    $0 = "QLIIFAX "

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_3__Portions_Copyright_c_198397_Borland_ {
  meta:
    description = "Borland Delphi 3 -> Portions Copyright (c) 1983,97 Borland"

  strings:
    $0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 37 20 42 6F 72 6C 61 6E 64 00 }

  condition:
    $0 at pe.entry_point
}

rule _Alpha_BMP_graphics_file_ {
  meta:
    description = "Alpha BMP graphics file"

  strings:
    $0 = { FF FF 00 01 64 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _GIF89a_Graphics_format_ {
  meta:
    description = "GIF89a Graphics format"

  strings:
    $0 = "GIF89a"

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_30_ {
  meta:
    description = "Borland Delphi 3.0"

  strings:
    $0 = { 55 8B EC 83 C4 F4 53 56 57 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_110_Eng__dulekxt__Borland_Delphi__Borland_Cpp_ {
  meta:
    description = "FSG 1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)"

  strings:
    $0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

  condition:
    $0 at pe.entry_point
}

rule _Ding_Boys_PElock_Phantasm_12__Ding_Boy_ {
  meta:
    description = "Ding Boy's PE-lock Phantasm 1.2 -> Ding Boy"

  strings:
    $0 = { 55 57 56 52 51 53 9C FA 90 E8 00 00 00 00 5D 8B D5 }

  condition:
    $0 at pe.entry_point
}

rule _SGI_Image_Graphics_format_ {
  meta:
    description = "SGI Image Graphics format"

  strings:
    $0 = { 01 DA 00 01 00 03 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_WATCOM_CCpp_EXE_ {
  meta:
    description = "PseudoSigner 0.1 [WATCOM C/C++ EXE"

  strings:
    $0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }
    $1 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Erdas_LANGIS_Image_graphics_format_ {
  meta:
    description = "Erdas LAN/GIS Image graphics format"

  strings:
    $0 = { 48 45 41 44 37 34 00 00 03 00 }

  condition:
    $0 at pe.entry_point
}

rule _HP48sx_graphics_format_ {
  meta:
    description = "HP-48sx graphics format"

  strings:
    $0 = "HPHP48-A"

  condition:
    $0 at pe.entry_point
}

rule _setupexe_Section44rsrc_ {
  meta:
    description = "setup.exe Section(4/4,.rsrc)"

  strings:
    $0 = { 00 00 00 00 00 00 00 00 04 00 00 00 00 00 04 00 03 00 00 00 30 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _FreeHand_Graphics_format_ {
  meta:
    description = "FreeHand Graphics format"

  strings:
    $0 = "AGD2"

  condition:
    $0 at pe.entry_point
}

rule _Img_Software_Set_graphics_file_ {
  meta:
    description = "Img Software Set graphics file"

  strings:
    $0 = "SCMI   1AT"

  condition:
    $0 at pe.entry_point
}

rule _CorelDraw_8_CDR_Graphics_format_ {
  meta:
    description = "CorelDraw 8 CDR Graphics format"

  strings:
    $0 = { 52 49 46 46 ?? ?? ?? ?? 43 44 52 38 }

  condition:
    $0 at pe.entry_point
}

rule _XWD_graphics_format_ {
  meta:
    description = "XWD graphics format"

  strings:
    $0 = { 00 00 00 71 00 00 00 07 00 00 00 02 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _MS_Visual_Cpp_v8_hgood_sig_but_is_it_MSVC_ {
  meta:
    description = "MS Visual C++ v.8 (h-good sig, but is it MSVC?)"

  strings:
    $0 = { E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_LCC_Win32_DLL_ {
  meta:
    description = "PseudoSigner 0.2 [LCC Win32 DLL"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }
    $1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }
    $2 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule _Sun_Icon_Graphics_format_ {
  meta:
    description = "Sun Icon Graphics format"

  strings:
    $0 = "/* Format_version=1,"

  condition:
    $0 at pe.entry_point
}

rule _EXE2COM_Encrypted_without_selfcheck_ {
  meta:
    description = "EXE2COM (Encrypted without selfcheck)"

  strings:
    $0 = { B3 ?? B9 ?? ?? BE ?? ?? BF ?? ?? EB ?? 54 69 ?? ?? ?? ?? 03 ?? ?? 32 C3 AA 43 49 E3 ?? EB ?? BE ?? ?? 8B C6 }

  condition:
    $0 at pe.entry_point
}

rule _EXE2COM_Limited_ {
  meta:
    description = "EXE2COM (Limited)"

  strings:
    $0 = { BE ?? ?? 8B 04 3D ?? ?? 74 ?? BA ?? ?? B4 09 CD 21 CD 20 }

  condition:
    $0 at pe.entry_point
}

rule _AVHRR_Graphics_format_ {
  meta:
    description = "AVHRR Graphics format"

  strings:
    $0 = { D5 C8 00 01 00 03 00 01 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_C_1987_or_Borland_Cpp_1991_ {
  meta:
    description = "Turbo C 1987 or Borland C++ 1991"

  strings:
    $0 = { FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 }

  condition:
    $0 at pe.entry_point
}

rule _MASMTASM__sig4_ {
  meta:
    description = "MASM/TASM - sig4"

  strings:
    $0 = { C3 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _GCCCYGWINMSYS_sign_ASL_ {
  meta:
    description = "GCC-CYGWIN-MSYS_sign_ASL"

  strings:
    $0 = { 55 89 E5 83 EC 08 A1 00 ?? ?? 00 85 C0 74 01 CC D9 7D FE 0F B7 4D FE 81 E1 C0 F0 FF FF 66 89 4D FE 0F B7 55 FE 81 CA 3F 03 00 00 66 89 55 FE D9 6D FE }

  condition:
    $0 at pe.entry_point
}

rule _Virtual_Image_Maker_Graphics_file_ {
  meta:
    description = "Virtual Image Maker Graphics file"

  strings:
    $0 = "SOMV"

  condition:
    $0 at pe.entry_point
}

rule _MSVCpp_DLL_v8_typical_OEP_recognized__h_ {
  meta:
    description = "MSVC++ DLL v.8 (typical OEP recognized - h)"

  strings:
    $0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? ?? ?? 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 ?? ?? ?? FF 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 ?? ?? ?? FF 83 FE 01 89 45 0C 75 0C 85 C0 75 37 57 50 53 E8 ?? ?? ?? FF 85 F6 74 05 83 FE 03 75 26 57 56 53 E8 ?? ?? ?? FF 85 C0 75 03 21 45 0C 83 7D 0C 00 74 11 A1 ?? ?? ?? ?? 85 C0 74 08 57 56 53 FF D0 89 45 0C 8B 45 0C 5F 5E 5B 5D C2 0C 00 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PiMP_Install_System_1x_ {
  meta:
    description = "Nullsoft PiMP Install System 1.x"

  strings:
    $0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 }

  condition:
    $0 at pe.entry_point
}

rule _EXE2COM_Method_1_ {
  meta:
    description = "EXE2COM (Method 1)"

  strings:
    $0 = { 8C DB BE ?? ?? 8B C6 B1 ?? D3 E8 03 C3 03 ?? ?? A3 ?? ?? 8C C8 05 ?? ?? A3 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_PE_loader_ {
  meta:
    description = "Borland PE loader"

  strings:
    $0 = { 8C C8 8E D8 8C 1E 42 00 8C 06 3C 00 8C 06 46 00 8C 06 4A 00 8B DC 83 C3 0F D1 EB D1 EB D1 EB D1 EB 8C D0 03 D8 2B 1E 3C 00 B8 00 4A CD 21 B8 42 FB BB 33 32 CD 2F 83 FB 00 0F 84 00 01 BA 52 00 1E 07 BB 3E 00 B8 00 4B CD 21 0F 83 00 01 8E 06 }

  condition:
    $0 at pe.entry_point
}

rule _Inno_Installer_v405_ {
  meta:
    description = "Inno Installer v4.0.5"

  strings:
    $0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 }

  condition:
    $0 at pe.entry_point
}

rule _hyings_PEArmor__hyingCCG_ {
  meta:
    description = "hying's PE-Armor -> hying[CCG"

  strings:
    $0 = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_32_RunTime_System_19881995__Open_Watcom_ {
  meta:
    description = "WATCOM C/C++ 32 Run-Time System 1988-1995 -> Open Watcom"

  strings:
    $0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }

  condition:
    $0 at pe.entry_point
}

rule _Gentee_Installer_Custom_ {
  meta:
    description = "Gentee Installer Custom"

  strings:
    $0 = { 55 8B EC 81 EC 14 04 00 00 53 56 57 6A 00 FF 15 08 41 40 00 68 00 50 40 00 FF 15 04 41 40 00 85 C0 74 29 6A 00 A1 00 20 40 00 ?? ?? ?? ?? 41 40 00 8B F0 6A 06 56 FF 15 1C 41 40 00 6A 03 56 FF }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__MS_Visual_Cpp__Borland_Cpp__Watcom_Cpp_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (MS Visual C++ / Borland C++ / Watcom C++)"

  strings:
    $0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_TREXE_ {
  meta:
    description = "Borland C++ (TR.EXE)"

  strings:
    $0 = { B4 0F CD 10 3C 03 74 05 B8 03 00 CD 10 BA 00 00 2E 89 16 00 01 8B 2E 02 00 8B 1E 2C 00 8E DA 8C 06 00 00 89 1E 00 00 89 2E 00 00 A1 00 00 8E C0 33 C0 8B D8 8B F8 B9 FF 7F FC F2 AE E3 00 43 26 38 05 75 F6 80 CD 80 F7 D9 89 0E 00 00 B9 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Setup_Factory_6003_Setup_Launcher_ {
  meta:
    description = "Setup Factory 6.0.0.3 Setup Launcher"

  strings:
    $0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PIMP_Install_System_v1x___Nullsoft_ {
  meta:
    description = "Nullsoft PIMP Install System v1.x ->  Nullsoft"

  strings:
    $0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_1992_1994_ {
  meta:
    description = "Borland C++ 1992, 1994"

  strings:
    $0 = { 8C C8 8E D8 8C 1E ?? ?? 8C 06 ?? ?? 8C 06 ?? ?? 8C 06 }

  condition:
    $0 at pe.entry_point
}

rule _Trilobytes_RNR_graphics_library_ {
  meta:
    description = "Trilobyte's RNR graphics library"

  strings:
    $0 = { 84 10 ?? ?? ?? ?? ?? ?? ?? 10 }

  condition:
    $0 at pe.entry_point
}

rule _Encapsulated_Postscript_graphics_file_v20_EPSF12_ {
  meta:
    description = "Encapsulated Postscript graphics file v2.0 EPSF-1.2"

  strings:
    $0 = "%!PS-Adobe-2.0 EPSF-1.2"

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Borland_Cue_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland Cue)"

  strings:
    $0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }

  condition:
    $0 at pe.entry_point
}

rule _Watcom_C_1994_ {
  meta:
    description = "Watcom C (1994)"

  strings:
    $0 = { FB B9 00 0B 8E C1 26 BB 00 09 83 C3 0F 80 E3 F0 26 89 1E 00 03 26 8C 1E 00 03 01 E3 83 C3 0F 80 E3 F0 8E D1 89 DC 26 89 1E 00 03 89 DA D1 EA D1 EA D1 EA D1 EA 26 80 3E 00 03 00 75 3F 8B 0E 02 00 8C C0 29 C1 39 CA 72 0D BB 01 00 B8 00 00 8C }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_3_2_ {
  meta:
    description = "Borland Delphi 3 (2)"

  strings:
    $0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 E8 00 00 FF FF E8 00 00 FF FF 33 C0 55 68 00 00 40 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 F0 33 C0 E8 00 00 FF FF 8B 45 F0 E8 00 00 FF FF 50 E8 00 00 FF FF }

  condition:
    $0 at pe.entry_point
}

rule _MacPaint_Graphics_format_ {
  meta:
    description = "MacPaint Graphics format"

  strings:
    $0 = { 00 00 00 02 FF FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _LCCWin32_1x_ {
  meta:
    description = "LCC-Win32 1.x"

  strings:
    $0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? 00 68 9A 10 40 00 50 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_02_Borland_Cpp_1999_ {
  meta:
    description = "PseudoSigner 0.2 [Borland C++ 1999"

  strings:
    $0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }
    $1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Borland_Cpp_Win16_1991_ {
  meta:
    description = "Borland C++ Win16 (1991)"

  strings:
    $0 = { 9A FF FF 00 00 0B C0 75 03 E9 D5 00 8C 06 16 00 89 1E 1C 00 89 36 1A 00 89 3E 18 00 89 16 1E 00 B8 FF FF 50 9A FF FF 00 00 33 C0 1E 07 BF DE 03 B9 7E 0A 2B CF FC F3 AA 33 C0 50 9A FF FF 00 00 FF 36 18 00 9A FF FF 00 00 0B C0 75 03 E9 91 00 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp_ {
  meta:
    description = "FSG 1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)"

  strings:
    $0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_Win32_1995_ {
  meta:
    description = "Borland C++ Win32 (1995)"

  strings:
    $0 = { A1 5A 00 00 00 C1 E0 02 A3 5E 00 00 00 57 51 33 C0 BF 00 00 00 00 B9 00 00 00 00 3B CF 76 05 2B CF FC F3 AA 59 5F 64 67 8B 16 04 00 89 15 6E 00 00 00 8B 42 F8 A3 66 00 00 00 8B 42 FC A3 6A 00 00 00 83 EA 04 89 15 00 00 00 00 83 EA 04 3B D4 }

  condition:
    $0 at pe.entry_point
}

rule _MASM32__TASM32_ {
  meta:
    description = "MASM32 / TASM32"

  strings:
    $0 = { 2B C0 50 E8 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Borland_Delphi_50_KOLMCK_ {
  meta:
    description = "PseudoSigner 0.1 [Borland Delphi 5.0 KOL/MCK"

  strings:
    $0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }
    $1 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0E 00 90 90 90 90 90 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0A 00 00 00 90 90 90 90 90 00 00 00 01 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _SafeDisc_4_ {
  meta:
    description = "SafeDisc 4"

  strings:
    $0 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

  condition:
    $0 at pe.entry_point
}

rule _Adlib_Sample_Audio_file_ {
  meta:
    description = "Adlib Sample Audio file"

  strings:
    $0 = "GOLD SAMPLE"

  condition:
    $0 at pe.entry_point
}

rule _Inno_Setup_Module_v5_ {
  meta:
    description = "Inno Setup Module v5"

  strings:
    $0 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? F3 FF FF E8 ?? F4 FF FF 33 C0 55 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Basic_v60_ {
  meta:
    description = "Microsoft Visual Basic v6.0"

  strings:
    $0 = { FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30 }

  condition:
    $0 at pe.entry_point
}

rule _Creative_Audio_file_ {
  meta:
    description = "Creative Audio file"

  strings:
    $0 = "Creative Voice File"

  condition:
    $0 at pe.entry_point
}

rule _WordPerfect_Graphics_format_ {
  meta:
    description = "WordPerfect Graphics format"

  strings:
    $0 = { FF 57 50 43 10 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Basic_50_ {
  meta:
    description = "Microsoft Visual Basic 5.0"

  strings:
    $0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Cue_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Cue)"

  strings:
    $0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Paint_Graphics_format_ {
  meta:
    description = "Microsoft Paint Graphics format"

  strings:
    $0 = "LinS"

  condition:
    $0 at pe.entry_point
}

rule _MingWin32_GCC_3x_ {
  meta:
    description = "MingWin32 GCC 3.x"

  strings:
    $0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55 }
    $1 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Nullsoft_Install_System_v198___Nullsoft_ {
  meta:
    description = "Nullsoft Install System v1.98 ->  Nullsoft"

  strings:
    $0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

  condition:
    $0 at pe.entry_point
}

rule _Inno_Setup_Module_v109a__JRSoftware_ {
  meta:
    description = "Inno Setup Module v1.09a -> JRSoftware"

  strings:
    $0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_Win32_1994_ {
  meta:
    description = "Borland C++ Win32 (1994)"

  strings:
    $0 = { A1 59 00 00 00 C1 E0 02 A3 5D 00 00 00 57 51 33 C0 BF 00 00 00 00 B9 00 00 00 00 3B CF 76 05 2B CF FC F3 AA 59 5F 64 67 8B 16 04 00 8B 42 F8 A3 61 00 00 00 8B 42 FC A3 65 00 00 00 83 EA 04 89 15 00 00 00 00 83 EA 04 3B D4 73 02 8B E2 6A 00 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_VideoLanClient_ {
  meta:
    description = "PseudoSigner 0.1 [Video-Lan-Client"

  strings:
    $0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }
    $1 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _CubiComp_PictureMaker_graphics_format_red_ {
  meta:
    description = "CubiComp PictureMaker graphics format (red)"

  strings:
    $0 = { 16 0C FF 02 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_C_or_Borland_Cpp_ {
  meta:
    description = "Turbo C or Borland C++"

  strings:
    $0 = { BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp__Open_Watcom_ {
  meta:
    description = "WATCOM C/C++ -> Open Watcom"

  strings:
    $0 = { E9 ?? ?? ?? 00 ?? ?? ?? 00 57 41 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_PiMP_Stub__SFX_ {
  meta:
    description = "Nullsoft PiMP Stub -> SFX"

  strings:
    $0 = { 81 EC ?? ?? ?? ?? 53 55 56 }

  condition:
    $0 at pe.entry_point
}

rule _ATT_Group_4_Graphics_format_ {
  meta:
    description = "AT&T Group 4 Graphics format"

  strings:
    $0 = { 01 00 ?? 00 3A 03 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_R_Incremental_Linker_Version_5128078_MASMTASM_ {
  meta:
    description = "Microsoft (R) Incremental Linker Version 5.12.8078 (MASM/TASM)"

  strings:
    $0 = { 6A 00 68 00 30 40 00 68 1E 30 40 00 6A 00 E8 0D 00 00 00 6A 00 E8 00 00 00 00 FF 25 00 20 40 00 FF 25 08 20 40 }

  condition:
    $0 at pe.entry_point
}

rule _MSLRH_032a_fake_MSVCpp_60_DLL__emadicius_ {
  meta:
    description = "MSLRH 0.32a (fake MSVC++ 6.0 DLL) -> emadicius"

  strings:
    $0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 }

  condition:
    $0 at pe.entry_point
}

rule _PDS_graphics_file_format_ {
  meta:
    description = "PDS graphics file format"

  strings:
    $0 = "IMAGEIDENTIFIER "

  condition:
    $0 at pe.entry_point
}

rule _Borland_C__Borland_Builder_ {
  meta:
    description = "Borland C / Borland Builder"

  strings:
    $0 = { 3B CF 76 05 2B CF FC F3 AA 59 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Basic_40_ {
  meta:
    description = "Microsoft Visual Basic 4.0"

  strings:
    $0 = { 68 ?? ?? ?? 00 E8 ?? FF FF FF 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_MinGW_GCC_2x_ {
  meta:
    description = "PseudoSigner 0.1 [MinGW GCC 2.x"

  strings:
    $0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }
    $1 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Microsoft_Bitmap_Graphics_format_ {
  meta:
    description = "Microsoft Bitmap Graphics format"

  strings:
    $0 = { 01 00 09 00 }

  condition:
    $0 at pe.entry_point
}

rule _CubiComp_PictureMaker_graphics_format_blue_ {
  meta:
    description = "CubiComp PictureMaker graphics format (blue)"

  strings:
    $0 = { 36 0C FF 02 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Delphi_v10_Unit_ {
  meta:
    description = "Delphi v1.0 Unit"

  strings:
    $0 = "DCU1"

  condition:
    $0 at pe.entry_point
}

rule _BAFF_BMPs_graphics_library_ {
  meta:
    description = "BAFF (BMP's) graphics library"

  strings:
    $0 = { 42 41 46 46 01 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Lotus_Graphics_format_ {
  meta:
    description = "Lotus Graphics format"

  strings:
    $0 = { 01 00 00 00 01 00 08 00 }

  condition:
    $0 at pe.entry_point
}

rule _Intel_DCX_Graphics_format_ {
  meta:
    description = "Intel DCX Graphics format"

  strings:
    $0 = { B1 68 DE 3A 04 10 00 }

  condition:
    $0 at pe.entry_point
}

rule _Windows_Icon_Graphics_format_ {
  meta:
    description = "Windows Icon Graphics format"

  strings:
    $0 = { 00 00 01 00 }

  condition:
    $0 at pe.entry_point
}

rule _MASM__TASM_ {
  meta:
    description = "MASM / TASM"

  strings:
    $0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00 }
    $1 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Image_Systems_Technology_Graphics_format_ {
  meta:
    description = "Image Systems Technology Graphics format"

  strings:
    $0 = { 03 3A ?? ?? 00 ?? 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Adobe_PhotoShop_Graphics_format_ {
  meta:
    description = "Adobe PhotoShop Graphics format"

  strings:
    $0 = { 38 42 50 53 00 01 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _IBM_IOCA_Graphics_format_ {
  meta:
    description = "IBM IOCA Graphics format"

  strings:
    $0 = { 00 11 D3 A6 FB }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_1991_ {
  meta:
    description = "Borland C++ 1991"

  strings:
    $0 = { 2E 8C 06 ?? ?? 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F }

  condition:
    $0 at pe.entry_point
}

rule _EXE2COM_Packed_ {
  meta:
    description = "EXE2COM (Packed)"

  strings:
    $0 = { BD ?? ?? 89 ?? ?? ?? 81 ?? ?? ?? ?? ?? 8C ?? ?? ?? 8C C8 05 ?? ?? 8E C0 BE ?? ?? 8B FE 0E 57 54 59 F3 A4 06 68 ?? ?? CB }

  condition:
    $0 at pe.entry_point
}

rule _GLBS_Install_Stub_32bit__Wise_ {
  meta:
    description = "GLBS Install Stub 32-bit -> Wise"

  strings:
    $0 = { 55 8B EC 81 EC 2C 05 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 54 40 40 00 FF 15 50 40 40 00 8B F8 89 7D F4 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D F4 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D F4 EB EF 80 3F 22 75 04 47 89 7D F4 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D F4 53 FF 15 6C }

  condition:
    $0 at pe.entry_point
}

rule _Safedisc_V450000__Macrovision_Corporation__SignByfly__20080117_ {
  meta:
    description = "Safedisc V4.50.000 -> Macrovision Corporation * Sign.By.fly * 20080117"

  strings:
    $0 = { 55 8B EC 60 BB 6E ?? ?? ?? B8 0D ?? ?? ?? 33 C9 8A 08 85 C9 74 0C B8 E4 ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 2B ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 D9 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 25 FC FF FF 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 96 50 B8 F9 ?? ?? ?? FF 10 61 5D EB 47 80 7C 24 08 00 75 40 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 02 ?? ?? ?? 89 4C 24 04 59 EB 29 50 B8 FD ?? ?? ?? FF 70 08 8B 40 0C FF D0 B8 FD ?? ?? ?? FF 30 8B 40 04 FF D0 58 B8 25 ?? ?? ?? FF 30 C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? 66 83 3D ?? ?? ?? ?? ?? 74 05 E9 91 FE FF FF C3 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_20_ {
  meta:
    description = "Nullsoft Install System 2.0"

  strings:
    $0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
    $1 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 02 23 00 00 BE ?? ?? ?? ?? 56 }
    $2 = { 83 EC 0C 53 55 56 57 C7 44 24 10 ?? ?? ?? ?? 33 DB C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 56 57 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 8D FF FF FF 8B 2D ?? ?? ?? ?? 85 C0 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule _DrHalo_or_DrGenius_Image_Graphics_format_ {
  meta:
    description = "DrHalo or DrGenius Image Graphics format"

  strings:
    $0 = { 3A 03 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _CubiComp_PictureMaker_graphics_format_green_ {
  meta:
    description = "CubiComp PictureMaker graphics format (green)"

  strings:
    $0 = { 26 0C FF 02 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_20b4_ {
  meta:
    description = "Nullsoft Install System 2.0b4"

  strings:
    $0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
    $1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Portable_BitMap_PBM_Graphics_format_ {
  meta:
    description = "Portable BitMap (PBM) Graphics format"

  strings:
    $0 = "P6\n"

  condition:
    $0 at pe.entry_point
}

rule _Upack_v028__039_relocated_image_base__Delphi_NET_DLL_or_something_else___Dwing_ {
  meta:
    description = "Upack v0.28 - 0.39 (relocated image base - Delphi, .NET, DLL or something else :) -> Dwing"

  strings:
    $0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 1C B1 30 8B 5D 0C 03 D1 FF 16 73 4C 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 18 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8B D5 03 56 38 FF 56 0C }

  condition:
    $0 at pe.entry_point
}

rule _GOES_graphics_file_ {
  meta:
    description = "GOES graphics file"

  strings:
    $0 = { C8 C4 D9 40 C1 D9 C5 C1 }

  condition:
    $0 at pe.entry_point
}

rule _JEDMICS_CCITT4_Graphics_format_ {
  meta:
    description = "JEDMICS CCITT4 Graphics format"

  strings:
    $0 = { 80 00 00 00 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Microsoft_Visual_Basic_50__60_ {
  meta:
    description = "PseudoSigner 0.1 [Microsoft Visual Basic 5.0 - 6.0"

  strings:
    $0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }
    $1 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Exact_Audio_Copy_ {
  meta:
    description = "Exact Audio Copy"

  strings:
    $0 = { E8 ?? ?? 5E FC 83 ?? ?? 81 ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 ?? ?? 07 ?? ?? ?? 07 B4 49 CD 21 BB FF FF B4 48 CD 21 }
    $1 = { E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 }
    $2 = { E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule _Borland_Delphi_6070_ {
  meta:
    description = "Borland Delphi 6.0-7.0"

  strings:
    $0 = { 55 8B EC 83 C4 ?? 53 33 C0 }

  condition:
    $0 at pe.entry_point
}

rule _TrueVision_Targa_Graphics_format_ {
  meta:
    description = "TrueVision Targa Graphics format"

  strings:
    $0 = { 00 00 02 00 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _MS_Visual_Cpp_v8__hgood_sig_but_is_it_MSVC_ {
  meta:
    description = "MS Visual C++ v.8  (h-good sig, but is it MSVC?)"

  strings:
    $0 = { E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00 00 01 EB 11 83 B8 74 00 00 01 0E 76 B8 33 C9 39 88 E8 00 00 01 0F 95 C1 8B C1 6A 01 A3 ?? ?? ?? 01 E8 ?? ?? 00 00 50 FF ?? ?? ?? 00 01 83 0D ?? ?? ?? 01 FF 83 0D ?? ?? ?? 01 FF 59 59 FF 15 ?? ?? 00 01 8B 0D ?? ?? ?? 01 89 08 FF 15 ?? ?? 00 01 8B 0D ?? ?? ?? 01 89 08 A1 ?? ?? 00 01 8B 00 A3 ?? ?? ?? 01 E8 ?? ?? 00 00 83 3D ?? ?? ?? 01 00 75 0C 68 ?? ?? ?? 01 FF 15 ?? ?? 00 01 59 E8 ?? ?? 00 00 33 C0 C3 CC CC CC CC CC }

  condition:
    $0 at pe.entry_point
}

rule _Setup_Factory_6x_Custom_ {
  meta:
    description = "Setup Factory 6.x Custom"

  strings:
    $0 = { 55 8B EC 6A FF 68 ?? 61 40 00 68 ?? 43 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? 61 40 00 33 D2 8A D4 89 15 A0 A9 40 00 8B C8 81 E1 FF 00 00 00 89 0D }

  condition:
    $0 at pe.entry_point
}

rule _EXE2COM_200_ {
  meta:
    description = "EXE2COM 2.00"

  strings:
    $0 = { E8 00 00 5B 81 EB 1D 00 8D B7 00 00 BF 00 01 B9 07 00 F3 A5 8D B7 FC 00 53 8C CF 83 C7 10 AD 09 C0 74 63 91 AD 01 F8 8E C0 AD 93 26 01 3F E2 F9 EB EC 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 31 2D 31 39 39 35 20 62 79 20 50 53 50 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_v20a7__Nullsoft_ {
  meta:
    description = "Nullsoft Install System v2.0a7 -> Nullsoft"

  strings:
    $0 = { 83 EC 0C 53 56 57 FF 15 BC 80 40 00 }

  condition:
    $0 at pe.entry_point
}

rule _Installer_VISE_Custom_ {
  meta:
    description = "Installer VISE Custom"

  strings:
    $0 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D }

  condition:
    $0 at pe.entry_point
}

rule _UPXFreak_01_Borland_Delphi__HMX0101_ {
  meta:
    description = "UPXFreak 0.1 (Borland Delphi) -> HMX0101"

  strings:
    $0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Imaging_Technology_Graphics_format_ {
  meta:
    description = "Imaging Technology Graphics format"

  strings:
    $0 = { 49 4D 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _AudioCD_file_ {
  meta:
    description = "Audio-CD file"

  strings:
    $0 = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 }

  condition:
    $0 at pe.entry_point
}

rule _Micrografix_Draw_Graphics_format_ {
  meta:
    description = "Micrografix Draw Graphics format"

  strings:
    $0 = { 01 FF 02 04 03 02 00 02 }

  condition:
    $0 at pe.entry_point
}

rule _GIF87a_Graphics_format_ {
  meta:
    description = "GIF87a Graphics format"

  strings:
    $0 = "GIF87a"

  condition:
    $0 at pe.entry_point
}

rule _VideoCD_file_ {
  meta:
    description = "Video-CD file"

  strings:
    $0 = { 52 49 46 46 ?? ?? ?? ?? 43 44 58 41 66 6D 74 }

  condition:
    $0 at pe.entry_point
}

rule _Amiga_IFFILBM_Graphics_format_ {
  meta:
    description = "Amiga IFF/ILBM Graphics format"

  strings:
    $0 = { 46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D 42 4D 48 44 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_for_Win16_1991_ {
  meta:
    description = "Borland C++ for Win16 1991"

  strings:
    $0 = { 9A FF FF 00 00 0B C0 75 ?? E9 ?? ?? 8C ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? B8 FF FF 50 9A FF FF 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Sierras_audio_file_ {
  meta:
    description = "Sierra`s audio file"

  strings:
    $0 = { 8D 0C 53 4F 4C 00 22 56 0D }

  condition:
    $0 at pe.entry_point
}

rule _AutoLogic_Graphics_format_ {
  meta:
    description = "AutoLogic Graphics format"

  strings:
    $0 = { FF 04 00 07 }

  condition:
    $0 at pe.entry_point
}

rule _FSG_v110_Eng__dulekxt__Borland_Delphi_40__50_ {
  meta:
    description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi 4.0 - 5.0)"

  strings:
    $0 = { EB 02 }

  condition:
    $0 at pe.entry_point
}

rule _GEM_Image_graphics_file_ {
  meta:
    description = "GEM Image graphics file"

  strings:
    $0 = { 00 01 00 08 00 04 00 02 }

  condition:
    $0 at pe.entry_point
}

rule _Inno_Installer_v512_ {
  meta:
    description = "Inno Installer v5.1.2"

  strings:
    $0 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 }
    $1 = { 9C 60 E8 00 00 00 00 58 BB DC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 50 00 00 68 D8 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _CALS_Raster_graphics_format_ {
  meta:
    description = "CALS Raster graphics format"

  strings:
    $0 = "srcdocid: "

  condition:
    $0 at pe.entry_point
}

rule _Windows_or_OS2_Graphics_format_ {
  meta:
    description = "Windows or OS/2 Graphics format"

  strings:
    $0 = "BM"

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_32_RunTime_System_19881994__Open_Watcom_ {
  meta:
    description = "WATCOM C/C++ 32 Run-Time System 1988-1994 -> Open Watcom"

  strings:
    $0 = { FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21 }

  condition:
    $0 at pe.entry_point
}

rule _RIX_graphics_file_ {
  meta:
    description = "RIX graphics file"

  strings:
    $0 = "RIX3"

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_Borland_Delphi_30_ {
  meta:
    description = "PseudoSigner 0.1 [Borland Delphi 3.0"

  strings:
    $0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    $1 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _LCCWin32_DLL_ {
  meta:
    description = "LCC-Win32 DLL"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 00 00 00 FF 75 10 FF 75 0C FF 75 08 A1 }

  condition:
    $0 at pe.entry_point
}

rule _PCPaintPictor_graphics_file_format_ {
  meta:
    description = "PCPaint/Pictor graphics file format"

  strings:
    $0 = { 34 12 ?? ?? ?? ?? 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Inset_Systems_IGF_graphics_file_ {
  meta:
    description = "Inset Systems IGF graphics file"

  strings:
    $0 = { 01 80 04 00 01 00 58 00 }

  condition:
    $0 at pe.entry_point
}

rule _Hitachi_Raster_Format_graphics_format_ {
  meta:
    description = "Hitachi Raster Format graphics format"

  strings:
    $0 = "CADC/KR RST"

  condition:
    $0 at pe.entry_point
}

rule _MingWin32_GCC_v34X_ {
  meta:
    description = "MingWin32 GCC v3.4.X"

  strings:
    $0 = { 55 89 E5 83 EC ?? C7 04 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 8D B4 26 ?? ?? ?? ?? 55 89 E5 83 EC ?? C7 04 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 8D B4 26 ?? ?? ?? ?? 55 8B 0D ?? ?? ?? ?? 89 E5 5D FF E1 8D 74 26 ?? 55 8B 0D ?? ?? ?? ?? 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 53 89 C1 0F B6 19 80 FB ?? 74 34 90 8D 74 26 }

  condition:
    $0 at pe.entry_point
}

rule _MacroMedia_ShockWave_Movie_file_ {
  meta:
    description = "MacroMedia ShockWave Movie file"

  strings:
    $0 = "FWS"

  condition:
    $0 at pe.entry_point
}

rule _PseudoSigner_01_LCC_Win32_1x_ {
  meta:
    description = "PseudoSigner 0.1 [LCC Win32 1.x"

  strings:
    $0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }
    $1 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Nullsoft_Install_System_20a0_ {
  meta:
    description = "Nullsoft Install System 2.0a0"

  strings:
    $0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 }

  condition:
    $0 at pe.entry_point
}

rule _MASMTASM__sig2_ {
  meta:
    description = "MASM/TASM - sig2"

  strings:
    $0 = { C2 ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_3__Portions_Copyright_c_198396_Borland_ {
  meta:
    description = "Borland Delphi 3 -> Portions Copyright (c) 1983,96 Borland"

  strings:
    $0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 36 20 42 6F 72 6C 61 6E 64 00 }

  condition:
    $0 at pe.entry_point
}

rule _Wise_Installer_Stub_11010291_ {
  meta:
    description = "Wise Installer Stub 1.10.1029.1"

  strings:
    $0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_32_RunTime_System_1989_1994_ {
  meta:
    description = "WATCOM C/C++ 32 Run-Time System 1989, 1994"

  strings:
    $0 = { 0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72 }

  condition:
    $0 at pe.entry_point
}

rule _CalComp_Graphics_format_ {
  meta:
    description = "CalComp Graphics format"

  strings:
    $0 = { 02 50 0A }

  condition:
    $0 at pe.entry_point
}

rule _Wicat_GED_Graphics_format_ {
  meta:
    description = "Wicat GED Graphics format"

  strings:
    $0 = { 0D 00 40 00 }

  condition:
    $0 at pe.entry_point
}

rule _VITec_graphics_file_format_ {
  meta:
    description = "VITec graphics file format"

  strings:
    $0 = { 00 5B 07 20 00 00 00 2C }

  condition:
    $0 at pe.entry_point
}

rule _setupexe_Section14text_ {
  meta:
    description = "setup.exe Section(1/4,.text)"

  strings:
    $0 = { 55 8B EC B8 7A 31 00 00 83 EC 08 53 56 57 A3 E8 5E 48 00 A3 EC 5E 48 }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_DLL_ {
  meta:
    description = "WATCOM C/C++ DLL"

  strings:
    $0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 }

  condition:
    $0 at pe.entry_point
}

rule _Real_Networks_VideoAudio_file_ {
  meta:
    description = "Real Networks Video/Audio file"

  strings:
    $0 = ".RMF"

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_5__Portions_Copyright_c_198399_Borland_ {
  meta:
    description = "Borland Delphi 5 -> Portions Copyright (c) 1983,99 Borland"

  strings:
    $0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 39 20 42 6F 72 6C 61 6E 64 00 }

  condition:
    $0 at pe.entry_point
}

rule _OS2_Icon_Graphics_format_ {
  meta:
    description = "OS/2 Icon Graphics format"

  strings:
    $0 = { 43 49 4E 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _setupexe_Section24rdata_ {
  meta:
    description = "setup.exe Section(2/4,.rdata)"

  strings:
    $0 = { 50 32 04 00 6A 32 04 00 00 00 00 00 EE 32 04 00 0C 33 04 00 2A 33 04 }

  condition:
    $0 at pe.entry_point
}

rule _MASMTASM__sig1_ {
  meta:
    description = "MASM/TASM - sig1"

  strings:
    $0 = { CC FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _EXE2COM_regular_ {
  meta:
    description = "EXE2COM (regular)"

  strings:
    $0 = { E9 8C CA 81 C3 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 0D }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Component_ {
  meta:
    description = "Borland Component"

  strings:
    $0 = { E9 ?? ?? FE FF 8D 40 00 }

  condition:
    $0 at pe.entry_point
}

rule _Amiga_AIFF_8SFX_Audio_file_ {
  meta:
    description = "Amiga AIFF 8SFX Audio file"

  strings:
    $0 = { 46 4F 52 4D ?? ?? ?? ?? 38 53 56 58 56 48 44 52 }

  condition:
    $0 at pe.entry_point
}

rule _ADEX_Graphics_format_ {
  meta:
    description = "ADEX Graphics format"

  strings:
    $0 = { 50 49 43 54 00 08 ?? 02 }

  condition:
    $0 at pe.entry_point
}

rule _REALbasic_ {
  meta:
    description = "REALbasic"

  strings:
    $0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_RunTime_systempDOS4GW_DOS_Extender_198893_ {
  meta:
    description = "WATCOM C/C++ Run-Time system+DOS4GW DOS Extender 1988-93"

  strings:
    $0 = { BF ?? ?? 8E D7 81 C4 ?? ?? BE ?? ?? 2B F7 8B C6 B1 ?? D3 }

  condition:
    $0 at pe.entry_point
}

rule PureBasic: Neil Hodgson {
  meta:
    author = "_pusher_"
    date   = "2016-07"

  strings:
    //make check for msvrt.dll
    $c0  = { 55 8B EC 6A 00 68 00 10 00 00 6A ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 10 00 00 00 A1 ?? ?? ?? ?? 50 6A ?? 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5D C3 CC CC CC CC CC CC CC CC CC }
    $c1  = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }
    $aa0 = "\x00MSVCRT.dll\x00" ascii
    $aa1 = "\x00CRTDLL.dll\x00" ascii

  condition:
    (for any of ($c0, $c1): ($ at pe.entry_point)) and
    (any of ($aa*)) and
    ((pe.linker_version.major == 2) and (pe.linker_version.minor == 50))
}

rule PureBasicDLL: Neil Hodgson {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

  condition:
    $a0 at pe.entry_point
}

rule PureBasic4xDLL: Neil Hodgson {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

  condition:
    $a0 at pe.entry_point
}

rule inno_h {
  meta:
    author      = "PEiD"
    description = "Inno-Setup Module"
    group       = "305"
    function    = "0"

  strings:
    $a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 ?? ?? 53 54 41 54 49 43 }

  condition:
    $a0 at pe.entry_point
}

rule nullsoft13 {
  meta:
    author      = "PEiD"
    description = "Nullsoft PiMP 1.3x"
    group       = "24"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

  condition:
    $a0 at pe.entry_point
}

rule nullsoft14 {
  meta:
    author      = "PEiD"
    description = "Nullsoft PiMP 1.x"
    group       = "24"
    function    = "0"

  strings:
    $a0 = { 83 EC 5C 53 55 56 57 FF 15 }

  condition:
    $a0 at pe.entry_point
}

rule nullsoft_h {
  meta:
    author      = "PEiD"
    description = "Nullsoft PiMP stub 1.x"
    group       = "24"
    function    = "0"

  strings:
    $a0 = { C3 83 EC ?? 53 56 57 FF 15 }

  condition:
    $a0 at pe.entry_point
}

rule nullsoft2_h {
  meta:
    author      = "PEiD"
    description = "Nullsoft PiMP 2.x stub"
    group       = "24"
    function    = "0"

  strings:
    $a0 = "Installer corrupted or incomplete.\r\n\r\nThis could be the result of a failed download or corruption from a virus.\r\n\r\nIf desperate, try the /NCRC command line switch (NOT recommended)"

  condition:
    $a0 at pe.entry_point
}

rule wiseinstall {
  meta:
    author      = "PEiD"
    description = "Wise Installer stub"
    group       = "306"
    function    = "0"

  strings:
    $a0 = { 53 54 55 42 33 32 2E 45 58 45 ?? 5F 4D 61 69 6E 57 6E 64 50 72 6F 63 40 31 36 ?? 5F 53 }

  condition:
    $a0 at pe.entry_point
}

rule msvcspx1 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ 6.0 SPx Method 1"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }

  condition:
    $a0 at pe.entry_point
}

rule msvcspx2 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ 6.0 SPx Method 2"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }

  condition:
    $a0 at pe.entry_point
}

rule NSISInstaller: NullSoft {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE }

  condition:
    $a0 at pe.entry_point
}

rule _Free_Pascal_v09910_ {
  meta:
    description = "Free Pascal v0.99.10"

  strings:
    $0 = { 64 A1 55 89 E5 6A FF 68 68 9A 10 40 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Pascal_v70_for_Windows_ {
  meta:
    description = "Borland Pascal v7.0 for Windows"

  strings:
    $0 = { A1 C1 A3 83 75 57 51 33 C0 }

  condition:
    $0 at pe.entry_point
}

rule _Stranik_13_ModulaCPascal_ {
  meta:
    description = "Stranik 1.3 Modula/C/Pascal"

  strings:
    $0 = { E9 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D }

  condition:
    $0 at pe.entry_point
}

rule PellesC300400450EXEX86CRTDLL {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 C7 45 FC ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? EB }

  condition:
    $a0 at pe.entry_point
}

rule GameGuardv20065xxdllsignbyhot_UNP {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }

  condition:
    $a0 at pe.entry_point
}

rule PoPa001PackeronPascalbagie {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }

  condition:
    $a0 at pe.entry_point
}

rule PellesC450DLLX86CRTLIB {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

  condition:
    $a0 at pe.entry_point
}

rule PellesC300400450EXEX86CRTLIB {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }

  condition:
    $a0 at pe.entry_point
}

rule PellesC2x4xDLLPelleOrinius {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

  condition:
    $a0 at pe.entry_point
}

rule GameGuardnProtect {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

  condition:
    $a0 at pe.entry_point
}

rule PellesC280290EXEX86CRTLIB {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 ?? ?? ?? ?? 59 A3 }

  condition:
    $a0 at pe.entry_point
}

rule PellesC28x45xPelleOrinius {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC }

  condition:
    $a0 at pe.entry_point
}

rule PellesC290300400DLLX86CRTLIB {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

  condition:
    $a0 at pe.entry_point
}

rule TMTPascalv040 {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }

  condition:
    $a0 at pe.entry_point
}

rule BeRoTinyPascalBeRo {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20 }

  condition:
    $a0 at pe.entry_point
}

rule GameGuardv20065xxexesignbyhot_UNP {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

  condition:
    $a0 at pe.entry_point
}

rule borland_delphi_dll {
  meta:
    author      = "_pusher_"
    description = "Borland Delphi DLL"
    date        = "2015-08"
    version     = "0.1"
    info        = "one is at pe.entry_point"

  strings:
    $c0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
    $c1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }

  condition:
    any of them
}

rule borland_component {
  meta:
    author      = "_pusher_"
    description = "Borland Component"
    date        = "2015-08"
    version     = "0.1"

  strings:
    $c0 = { E9 ?? ?? ?? FF 8D 40 00 }

  condition:
    $c0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C___ {
  strings:
    $a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
    $a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule Nullsoft_Install_System_v2_0 {
  strings:
    $a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D5 E8 6A FF FF FF 85 C0 0F 84 57 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 9C 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 75 0A C6 44 24 14 22 BE 01 40 43 00 FF 74 24 14 56 E8 8A 23 00 00 50 FF 15 80 71 40 00 8B F8 89 7C 24 18 EB 61 80 F9 20 75 06 40 80 38 20 74 FA 80 38 22 C6 44 24 14 20 75 06 40 C6 44 24 14 22 80 38 2F 75 31 40 80 38 53 75 0E 8A 48 01 80 C9 20 80 F9 20 75 03 }

  condition:
    $a0 at pe.entry_point
}

rule Inno_Setup_Module_Heuristic_Mode {
  strings:
    $a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? FF FF }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_vx_x__Component_ {
  strings:
    $a0 = { C3 E9 ?? ?? ?? FF 8D 40 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_2_rule__Watcom_C_C___DLL______Anorganix {
  strings:
    $a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__Borland_Delphi_3_0______Anorganix {
  strings:
    $a0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a0 at pe.entry_point
}

rule Inno_Setup_Module_v1_09a {
  strings:
    $a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_Install_System_v1_xx {
  strings:
    $a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 56 56 56 89 75 E4 E8 C1 C9 FF FF 8B 1D 68 70 40 00 83 C4 0C 89 45 E8 89 75 F0 6A 02 56 6A FC 57 FF D3 89 45 FC 8D 45 F8 56 50 8D 45 E4 6A 04 50 57 FF 15 48 70 40 00 85 C0 75 07 BB 7C 9E 40 00 EB 7A 56 56 56 57 FF D3 39 75 FC 7E 62 BF 74 A2 40 00 B8 00 10 00 00 39 45 FC 7F 03 8B 45 FC 8D 4D F8 56 51 50 57 FF 75 EC FF 15 48 70 40 00 85 C0 74 5A FF 75 F8 57 FF 75 E8 E8 4D C9 FF FF 89 45 E8 8B 45 F8 29 45 FC 83 C4 0C 39 75 F4 75 11 57 E8 D3 F9 FF FF 85 C0 59 74 06 8B 45 F0 89 45 F4 8B 45 F8 01 45 F0 39 75 FC }
    $a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule Nullsoft_PiMP_Stub_v1_x {
  strings:
    $a0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 3E 2F }

  condition:
    $a0 at pe.entry_point
}

rule Inno_Setup_Module_v3_0_4_beta_v3_0_6_v3_0_7 {
  strings:
    $a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_v6_0___v7_0 {
  strings:
    $a0 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $a1 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
    $a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FB FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 8B 15 ?? ?? ?? ?? E8 ?? ?? FF FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF E8 ?? ?? FB FF 8D 40 }
    $a3 = { 55 8B EC 83 C4 F0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point
}

rule rule__MSLRH__v0_32a__fake_MSVC___6_0_DLL_____emadicius {
  strings:
    $a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__REALBasic______Anorganix {
  strings:
    $a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_2_rule__Borland_Delphi_Setup_Module______Anorganix {
  strings:
    $a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_Install_System_v2_0_RC2 {
  strings:
    $a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D3 E8 6A FF FF FF 85 C0 0F 84 59 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 B9 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 40 43 00 8B 3D 18 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }

  condition:
    $a0 at pe.entry_point
}

rule Inno_Setup_Module_ren {
  strings:
    $a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Pascal_v7_0_for_Windows {
  strings:
    $a0 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____MASM32_ {
  strings:
    $a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__MinGW_GCC_2_x______Anorganix {
  strings:
    $a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

  condition:
    $a0 at pe.entry_point
}

rule rule__MSLRH__v0_32a__fake_MSVC___DLL_Method_4_____emadicius {
  strings:
    $a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C_____ASM_ {
  strings:
    $a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

  condition:
    $a0 at pe.entry_point
}

rule MingWin32_GCC_V3_X_____Sign_By_fly {
  strings:
    $a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}

rule AHTeam_EP_Protector_0_3__fake_Borland_Delphi_6_0_7_0_____FEUERRADER {
  strings:
    $a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }

  condition:
    $a0 at pe.entry_point
}

rule Watcom_C_C__ {
  strings:
    $a0 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 31 39 38 38 2D 31 39 39 35 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_PIMP_Install_System_v1_x {
  strings:
    $a0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}

rule UPXFreak_v0_1__Borland_Delphi_____HMX0101 {
  strings:
    $a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_v5_0_KOL {
  strings:
    $a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_20__Eng_____dulek_xt_____MASM32___TASM32_ {
  strings:
    $a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Borland_C___1999_ {
  strings:
    $a0 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_C__ {
  strings:
    $a0 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 05 2B CF FC F3 AA 59 5F }

  condition:
    $a0 at pe.entry_point
}

rule Microsoft_Visual_Basic_v6_0 {
  strings:
    $a0 = { FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_Basic_5_0___6_0_ {
  strings:
    $a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

  condition:
    $a0 at pe.entry_point
}

rule WATCOM_C_C___32_Run_Time_System_1988_1995 {
  strings:
    $a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }

  condition:
    $a0 at pe.entry_point
}

rule WATCOM_C_C___32_Run_Time_System_1988_1994 {
  strings:
    $a0 = { FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21 }

  condition:
    $a0 at pe.entry_point
}

rule MinGW_GCC_v2_x {
  strings:
    $a0 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }
    $a1 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule FSG_v1_20__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C___ {
  strings:
    $a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

  condition:
    $a0 at pe.entry_point
}

rule MinGW_GCC_DLL_v2xx_ren {
  strings:
    $a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 68 }

  condition:
    $a0 at pe.entry_point
}

rule UPX_2_90_rule__LZMA___Delphi_stub_____Markus_Oberhumer__Laszlo_Molnar___John_Reiser {
  strings:
    $a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Borland_C___ {
  strings:
    $a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__LCC_Win32_1_x______Anorganix {
  strings:
    $a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_2_rule__Borland_Delphi_DLL______Anorganix {
  strings:
    $a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_Basic___MASM32_ {
  strings:
    $a0 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

  condition:
    $a0 at pe.entry_point
}

rule TASM___MASM {
  strings:
    $a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

  condition:
    $a0 at pe.entry_point
}

rule Free_Pascal_v1_0_10__win32_GUI_ {
  strings:
    $a0 = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }

  condition:
    $a0 at pe.entry_point
}

rule Ding_Boy_s_PE_lock_Phantasm_v1_0___v1_1 {
  strings:
    $a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__Video_Lan_Client______Anorganix {
  strings:
    $a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32___Microsoft_Visual_Basic_ {
  strings:
    $a0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

  condition:
    $a0 at pe.entry_point
}

rule Ding_Boy_s_PE_lock_Phantasm_v0_8 {
  strings:
    $a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

  condition:
    $a0 at pe.entry_point
}

rule PureBasic_4_x____Neil_Hodgson {
  strings:
    $a0 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_v3_0 {
  strings:
    $a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }
    $a1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__WATCOM_C_C___EXE______Anorganix {
  strings:
    $a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

  condition:
    $a0 at pe.entry_point
}

rule FASM_v1_3x {
  strings:
    $a0 = { 6A ?? FF 15 ?? ?? ?? ?? A3 }

  condition:
    $a0 at pe.entry_point
}

rule Wise_Installer_Stub_v1_10_1029_1 {
  strings:
    $a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_PIMP_Install_System_v1_3x {
  strings:
    $a0 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_Install_System_v2_0b4 {
  strings:
    $a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 68 E4 91 40 00 56 FF D3 E8 7C FF FF FF 85 C0 0F 84 59 01 00 00 BE E0 66 42 00 56 FF 15 68 70 40 00 68 D8 91 40 00 56 E8 FE 27 00 00 57 FF 15 BC 70 40 00 BE 00 C0 42 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 C0 42 00 22 A3 E0 6E 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 C0 42 00 8B 3D 10 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }
    $a1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule BobSoft_Mini_Delphi____BoB___BobSoft {
  strings:
    $a0 = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }
    $a1 = { 55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule Borland_Delphi_v6_0 {
  strings:
    $a0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 }
    $a1 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule Borland_Delphi_v6_0_KOL {
  strings:
    $a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }

  condition:
    $a0 at pe.entry_point
}

rule Inno_Setup_Module_v2_0_18 {
  strings:
    $a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }

  condition:
    $a0 at pe.entry_point
}

rule REALbasic {
  strings:
    $a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_Install_System_v1_98 {
  strings:
    $a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____bart_xt_____Watcom_C_C___EXE_ {
  strings:
    $a0 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_Install_System_v2_0a0 {
  strings:
    $a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__Borland_Delphi_5_0_KOL_MCK______Anorganix {
  strings:
    $a0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

  condition:
    $a0 at pe.entry_point
}

rule Free_Pascal_v0_99_10 {
  strings:
    $a0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Borland_C___ {
  strings:
    $a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
    $a1 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi_2_0_ {
  strings:
    $a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

  condition:
    $a0 at pe.entry_point
}

rule Wise_Installer_Stub_ren {
  strings:
    $a0 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 }
    $a1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF 89 45 FC 0F 84 7B 01 00 00 8D 85 90 FC FF FF 50 56 FF 15 28 20 40 00 8D 85 98 FE FF FF 50 53 8D 85 90 FC FF FF 68 10 30 40 00 50 FF 15 24 20 40 00 53 68 80 00 00 00 6A 02 53 53 8D 85 98 FE FF FF 68 00 00 00 40 50 FF D7 83 F8 FF 89 45 F4 0F 84 2F 01 00 00 53 53 53 6A 02 53 FF 75 FC FF 15 00 20 40 00 53 53 53 6A 04 50 89 45 F8 FF 15 1C 20 40 00 8B F8 C7 45 FC 01 00 00 00 8D 47 01 8B 08 81 F9 4D 5A 9A 00 74 08 81 F9 4D 5A 90 00 75 06 80 78 04 03 74 0D FF 45 FC 40 81 7D FC 00 80 00 00 7C DB 8D 4D F0 53 51 68 }
    $a2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D ?? 53 FF 15 ?? 40 40 00 80 3F 2F 89 45 ?? 75 ?? 8A 47 01 3C 53 74 04 3C 73 75 06 89 35 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__Borland_Delphi_6_0___7_0______Anorganix {
  strings:
    $a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__Microsoft_Visual_Basic_5_0___6_0______Anorganix {
  strings:
    $a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___4_x___LCC_Win32_1_x_ {
  strings:
    $a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_20__Eng_____dulek_xt_____Borland_C___ {
  strings:
    $a0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

  condition:
    $a0 at pe.entry_point
}

rule __PseudoSigner_0_1_rule__LCC_Win32_DLL______Anorganix {
  strings:
    $a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }

  condition:
    $a0 at pe.entry_point
}

rule Microsoft_Visual_Basic_v5_0 {
  strings:
    $a0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_20__Eng_____dulek_xt_____Borland_Delphi___Borland_C___ {
  strings:
    $a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

  condition:
    $a0 at pe.entry_point
}

rule Stranik_1_3_Modula_C_Pascal {
  strings:
    $a0 = { E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? 00 ?? ?? 00 ?? 00 ?? 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_v5_0_KOL_MCK {
  strings:
    $a0 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 00 00 }

  condition:
    $a0 at pe.entry_point
}

rule Inno_Setup_Module_v1_2_9 {
  strings:
    $a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_C___for_Win32_1994 {
  strings:
    $a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 57 51 33 C0 BF }

  condition:
    $a0 at pe.entry_point
}

rule Ding_Boy_s_PE_lock_Phantasm_v1_5b3 {
  strings:
    $a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_DLL_ {
  strings:
    $a0 = { 55 8B EC 83 C4 B4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 40 }

  condition:
    $a0 at pe.entry_point
}

rule Free_Pascal_v1_0_10__win32_console_ {
  strings:
    $a0 = { C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC }

  condition:
    $a0 at pe.entry_point
}

rule Free_Pascal_v1_06 {
  strings:
    $a0 = { C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}

rule Borland_Delphi_v4_0___v5_0 {
  strings:
    $a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
    $a1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 }
    $a2 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

rule Safedisc_V4_50_000____Macrovision_Corporation____Sign_By_fly___20080117 {
  strings:
    $a0 = { 55 8B EC 60 BB 6E ?? ?? ?? B8 0D ?? ?? ?? 33 C9 8A 08 85 C9 74 0C B8 E4 ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 2B ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 D9 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 25 FC FF FF 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 96 50 B8 F9 ?? ?? ?? FF 10 61 5D EB 47 80 7C 24 08 00 75 40 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 02 ?? ?? ?? 89 4C 24 04 59 EB 29 50 B8 FD ?? ?? ?? FF 70 08 8B 40 0C FF D0 B8 FD ?? ?? ?? FF 30 8B 40 04 FF D0 58 B8 25 ?? ?? ?? FF 30 C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? 66 83 3D ?? ?? ?? ?? ?? 74 05 E9 91 FE FF FF C3 }

  condition:
    $a0 at pe.entry_point
}

rule Nullsoft_Install_System_v2_0b2__v2_0b3 {
  strings:
    $a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }

  condition:
    $a0 at pe.entry_point
}

rule FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32_ {
  strings:
    $a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

  condition:
    $a0 at pe.entry_point
}

rule _Pelles_C_300_400_450_EXE_X86_CRTLIB_ {
  meta:
    description = "Pelles C 3.00, 4.00, 4.50 EXE (X86 CRT-LIB)"

  strings:
    $0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }

  condition:
    $0 at pe.entry_point
}

rule _GameGuard_v20065xx_exe__sign_by_hot_UNP_ {
  meta:
    description = "GameGuard v2006.5.x.x (*.exe) -> sign by hot_UNP"

  strings:
    $0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

  condition:
    $0 at pe.entry_point
}

rule _PoPa_001_Packer_on_Pascal__bagie_ {
  meta:
    description = "PoPa 0.01 (Packer on Pascal) -> bagie"

  strings:
    $0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_2x4x_DLL__Pelle_Orinius_ {
  meta:
    description = "Pelles C 2.x-4.x DLL -> Pelle Orinius"

  strings:
    $0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_280_290_EXE_X86_CRTLIB_ {
  meta:
    description = "Pelles C 2.80 -2.90 EXE (X86 CRT-LIB)"

  strings:
    $0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 ?? ?? ?? ?? 59 A3 }

  condition:
    $0 at pe.entry_point
}

rule _GameGuard_v20065xx_dll__sign_by_hot_UNP_ {
  meta:
    description = "GameGuard v2006.5.x.x (*.dll) -> sign by hot_UNP"

  strings:
    $0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_300_400_450_EXE_X86_CRTDLL_ {
  meta:
    description = "Pelles C 3.00, 4.00, 4.50 EXE (X86 CRT-DLL)"

  strings:
    $0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 C7 45 FC ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? EB }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_28x45x__Pelle_Orinius_ {
  meta:
    description = "Pelles C 2.8.x-4.5.x -> Pelle Orinius"

  strings:
    $0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_450_DLL_X86_CRTLIB_ {
  meta:
    description = "Pelles C 4.50 DLL (X86 CRT-LIB)"

  strings:
    $0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

  condition:
    $0 at pe.entry_point
}

rule _BeRo_Tiny_Pascal__BeRo_ {
  meta:
    description = "BeRo Tiny Pascal -> BeRo"

  strings:
    $0 = { E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20 }

  condition:
    $0 at pe.entry_point
}

rule _GameGuard__nProtect_ {
  meta:
    description = "GameGuard - nProtect"

  strings:
    $0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_290_300_400_DLL_X86_CRTLIB_ {
  meta:
    description = "Pelles C 2.90, 3.00, 4.00 DLL (X86 CRT-LIB)"

  strings:
    $0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

  condition:
    $0 at pe.entry_point
}

rule _TMTPascal_v040_ {
  meta:
    description = "TMT-Pascal v0.40"

  strings:
    $0 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }

  condition:
    $0 at pe.entry_point
}

rule _JPEG_Graphics_format_p_description_ {
  meta:
    description = "JPEG Graphics format + description"

  strings:
    $0 = { FF D8 FF FE 00 27 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_20_RC2_ {
  meta:
    description = "Nullsoft Install System 2.0 RC2"

  strings:
    $0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

  condition:
    $0 at pe.entry_point
}

rule _TIFF_Graphics_file_IBM_ {
  meta:
    description = "TIFF Graphics file (IBM)"

  strings:
    $0 = "II*"

  condition:
    $0 at pe.entry_point
}

rule _FreePascal_200_Win32__Berczi_Gabor_Pierre_Muller__Peter_Vreman_ {
  meta:
    description = "FreePascal 2.0.0 Win32 -> (Berczi Gabor, Pierre Muller & Peter Vreman)"

  strings:
    $0 = { 55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 6A 00 64 FF 35 00 00 00 00 89 E0 A3 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 5D E8 ?? ?? ?? ?? C9 C3 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Pascal_v70_ {
  meta:
    description = "Borland Pascal v7.0"

  strings:
    $0 = { B8 ?? ?? 8E D8 8C ?? ?? ?? 8C D3 8C C0 2B D8 8B C4 05 ?? ?? C1 ?? ?? 03 D8 B4 ?? CD 21 0E }
    $1 = { B8 ?? ?? BB ?? ?? 8E D0 8B E3 8C D8 8E C0 0E 1F A1 ?? ?? 25 ?? ?? A3 ?? ?? E8 ?? ?? 83 3E ?? ?? ?? 75 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Stony_Brook_Pascalp_v70_ {
  meta:
    description = "Stony Brook Pascal+ v7.0"

  strings:
    $0 = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 81 EC ?? ?? B8 ?? ?? 0E 50 9A ?? ?? ?? ?? BE ?? ?? 1E 0E BF ?? ?? 1E 07 1F FC }

  condition:
    $0 at pe.entry_point
}

rule _Stony_Brook_Pascal_v614_ {
  meta:
    description = "Stony Brook Pascal v6.14"

  strings:
    $0 = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 ?? EC ?? ?? 9A }

  condition:
    $0 at pe.entry_point
}

rule _MPEG_movie_file_ {
  meta:
    description = "MPEG movie file"

  strings:
    $0 = { 00 00 01 BA 2F FF FD E6 C1 80 18 61 00 00 01 BB }

  condition:
    $0 at pe.entry_point
}

rule _Free_Pascal_v1010_win32_console_ {
  meta:
    description = "Free Pascal v1.0.10 (win32 console)"

  strings:
    $0 = { C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_v50_Unit_ {
  meta:
    description = "Turbo Pascal v5.0 Unit"

  strings:
    $0 = { 54 50 55 35 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_v40_Unit_ {
  meta:
    description = "Turbo Pascal v4.0 Unit"

  strings:
    $0 = { 54 50 55 30 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_or_Borland_Pascal_v70_ {
  meta:
    description = "Turbo or Borland Pascal v7.0"

  strings:
    $0 = { 9A ?? ?? ?? ?? C8 ?? ?? ?? 9A ?? ?? ?? ?? 09 C0 75 ?? EB ?? 8D ?? ?? ?? 16 57 6A ?? 9A ?? ?? ?? ?? BF ?? ?? 1E 57 68 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_3_ {
  meta:
    description = "Turbo Pascal 3"

  strings:
    $0 = { E9 00 00 90 90 CD AB 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 38 35 20 42 4F 52 4C 41 4E 44 20 49 6E 63 02 04 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_v60_Unit_ {
  meta:
    description = "Turbo Pascal v6.0 Unit"

  strings:
    $0 = { 54 50 55 39 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_v20_1984_ {
  meta:
    description = "Turbo Pascal v2.0 1984"

  strings:
    $0 = { 90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 34 }

  condition:
    $0 at pe.entry_point
}

rule _Watcom_CCpp_ {
  meta:
    description = "Watcom C/C++"

  strings:
    $0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 }
    $1 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 31 39 38 38 2D 31 39 39 35 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E 00 00 00 00 00 00 }
    $2 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2
}

rule _SafeDiscSafeCast_2xx__3xx__Macrovision_ {
  meta:
    description = "SafeDisc/SafeCast 2.xx - 3.xx -> Macrovision"

  strings:
    $0 = { 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C }
    $1 = { 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 97 50 A1 29 ?? ?? ?? ?? D0 61 5D EB 46 80 7C 24 08 00 75 3F 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 4C 24 04 59 EB 28 50 B8 2D ?? ?? ?? ?? 70 08 8B 40 0C FF D0 B8 2D ?? ?? ?? ?? 30 8B 40 04 FF D0 58 FF 35 ?? ?? ?? ?? C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? CC CC 81 EC E8 02 00 00 53 55 56 57 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _MPEG_Video_file_2_ {
  meta:
    description = "MPEG Video file (2)"

  strings:
    $0 = { 00 00 01 B3 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Pascal_70_for_Windows_ {
  meta:
    description = "Borland Pascal 7.0 for Windows"

  strings:
    $0 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_Help_File_ {
  meta:
    description = "Turbo Pascal Help File"

  strings:
    $0 = { 54 55 52 ?? ?? ?? 50 41 53 ?? ?? ?? ?? 48 45 4C 50 }

  condition:
    $0 at pe.entry_point
}

rule _Pelles_C_290_EXE_X86_CRTLIB_ {
  meta:
    description = "Pelles C 2.90 EXE (X86 CRT-LIB)"

  strings:
    $0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }

  condition:
    $0 at pe.entry_point
}

rule _Free_Pascal_v1010_win32_GUI_ {
  meta:
    description = "Free Pascal v1.0.10 (win32 GUI)"

  strings:
    $0 = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }

  condition:
    $0 at pe.entry_point
}

rule _Trilobytes_JPEG_graphics_Library_ {
  meta:
    description = "Trilobyte's JPEG graphics Library"

  strings:
    $0 = { 84 10 FF FF FF FF 1E 00 01 10 08 00 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _FreePascal_200_Win32__Bczi_Gor_Pierre_Muller__Peter_Vreman_ {
  meta:
    description = "FreePascal 2.0.0 Win32 -> (B?czi G?or, Pierre Muller & Peter Vreman)"

  strings:
    $0 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 00 E8 C5 01 00 00 89 D8 E8 3E 02 00 00 E8 B9 01 00 00 E8 54 02 00 00 8B 5D FC C9 C3 8D 76 00 00 00 00 00 00 00 00 00 00 00 00 00 55 89 E5 C6 05 10 80 40 00 00 E8 D1 03 00 00 6A 00 64 FF 35 00 00 00 00 89 E0 A3 ?? 70 40 00 55 31 ED 89 E0 A3 20 80 40 00 66 8C D5 89 2D 30 80 40 00 E8 B9 03 00 00 31 ED E8 72 FF FF FF 5D E8 BC 03 00 00 C9 C3 00 00 00 00 00 00 00 00 00 00 55 89 E5 83 EC 08 E8 15 04 00 00 A1 ?? 70 40 00 89 45 F8 B8 01 00 00 00 89 45 FC 3B 45 F8 7F 2A FF 4D FC 90 FF 45 FC 8B 45 FC 83 3C C5 ?? 70 40 00 00 74 09 8B 04 C5 ?? 70 40 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_60__70_ {
  meta:
    description = "Borland Delphi 6.0 - 7.0"

  strings:
    $0 = { 55 8B EC B9 07 00 00 }
    $1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $2 = { 55 8B EC 83 C4 F0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule _HSI_JPEG_graphics_file_ {
  meta:
    description = "HSI JPEG graphics file"

  strings:
    $0 = { 68 73 69 31 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _FreePascal_104_Win32__Berczi_Gabor_Pierre_Muller__Peter_Vreman_ {
  meta:
    description = "FreePascal 1.0.4 Win32 -> (Berczi Gabor, Pierre Muller & Peter Vreman)"

  strings:
    $0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }
    $1 = { 55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? DB E3 D9 2D ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 5D E8 ?? ?? ?? ?? C9 C3 }

  condition:
    $0 at pe.entry_point or $1
}

rule _EXE2COM_With_CRC_check_ {
  meta:
    description = "EXE2COM (With CRC check)"

  strings:
    $0 = { B3 ?? B9 ?? ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 43 49 32 E4 03 D0 E3 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_v30_1985_ {
  meta:
    description = "Turbo Pascal v3.0 1985"

  strings:
    $0 = { 90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 35 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_or_Borland_Pascal_v7x_Unit_ {
  meta:
    description = "Turbo or Borland Pascal v7.x Unit"

  strings:
    $0 = { 54 50 55 51 00 }

  condition:
    $0 at pe.entry_point
}

rule _Can2Exe_v001_ {
  meta:
    description = "Can2Exe v0.01"

  strings:
    $0 = { 0E 1F 0E 07 E8 ?? ?? E8 ?? ?? 3A C6 73 }

  condition:
    $0 at pe.entry_point
}

rule _FreePascal_104_Win32_DLL__Berczi_Gabor_Pierre_Muller__Peter_Vreman_ {
  meta:
    description = "FreePascal 1.0.4 Win32 DLL -> (Berczi Gabor, Pierre Muller & Peter Vreman)"

  strings:
    $0 = { C6 05 ?? ?? ?? ?? 00 55 89 E5 53 56 57 8B 7D 08 89 3D ?? ?? ?? ?? 8B 7D 0C 89 3D ?? ?? ?? ?? 8B 7D 10 89 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 5D C2 0C 00 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_Desktop_File_ {
  meta:
    description = "Turbo Pascal Desktop File"

  strings:
    $0 = "Turbo Pascal Desktop"

  condition:
    $0 at pe.entry_point
}

rule _FreePascal_200_Win32_ {
  meta:
    description = "FreePascal 2.0.0 Win32"

  strings:
    $0 = { C6 05 ?? ?? ?? ?? 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }
    $1 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Turbo_Pascal_Configuration_File_ {
  meta:
    description = "Turbo Pascal Configuration File"

  strings:
    $0 = "Turbo Pascal Configuration"

  condition:
    $0 at pe.entry_point
}

rule _TIFF_Graphics_file_Macintosh_ {
  meta:
    description = "TIFF Graphics file (Macintosh)"

  strings:
    $0 = { 4D 4D 00 }

  condition:
    $0 at pe.entry_point
}

rule _Free_Pascal_09910_ {
  meta:
    description = "Free Pascal 0.99.10"

  strings:
    $0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

  condition:
    $0 at pe.entry_point
}

rule _JPEG__GIF_library_file_ {
  meta:
    description = "JPEG & GIF library file"

  strings:
    $0 = { 00 05 16 07 00 02 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _TMTPascals_Unit_file_ {
  meta:
    description = "TMT-Pascal's Unit file"

  strings:
    $0 = { 50 00 00 00 53 50 46 50 }

  condition:
    $0 at pe.entry_point
}

rule _Turbo_Pascal_v55_Unit_ {
  meta:
    description = "Turbo Pascal v5.5 Unit"

  strings:
    $0 = { 54 50 55 36 00 }

  condition:
    $0 at pe.entry_point
}

rule _GCC_RealBasic_FreePascal_signII_ASL_ {
  meta:
    description = "GCC RealBasic/ FreePascal signII *ASL"

  strings:
    $0 = { 55 89 E5 83 EC 18 83 3D 00 ?? ?? 00 00 74 01 CC D9 7D FE 0F B7 45 FE 25 C0 F0 FF FF 66 89 45 FE 0F B7 45 FE 0D 3F 03 00 00 66 89 45 FE D9 6D FE 83 C4 }

  condition:
    $0 at pe.entry_point
}

rule _GameGuard_v20065xx_exe_ {
  meta:
    description = "GameGuard v2006.5.x.x (*.exe)"

  strings:
    $0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }
    $1 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Borland_Pascal_v70_Protected_Mode_ {
  meta:
    description = "Borland Pascal v7.0 Protected Mode"

  strings:
    $0 = { B8 ?? ?? BB ?? ?? 8E D0 8B E3 8C D8 8E C0 0E 1F A1 ?? ?? 25 ?? ?? A3 ?? ?? E8 ?? ?? 83 3E ?? ?? ?? 75 }

  condition:
    $0 at pe.entry_point
}

rule lcc_win32 {
  meta:
    author      = "PEiD"
    description = "LCC Win32 1.x -> Jacob Navia"
    group       = "12"
    function    = "0"

  strings:
    $a0 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }

  condition:
    $a0 at pe.entry_point
}

rule watcom_c_h {
  meta:
    author      = "PEiD"
    description = "Watcom C/C++ EXE Heuristic Mode"
    group       = "17"
    function    = "0"

  strings:
    $a0 = { 53 51 52 55 89 E5 83 EC 08 B8 01 ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 03 }

  condition:
    $a0 at pe.entry_point
}


