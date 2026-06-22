import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "macho"
import "math"
import "time"

rule ASProtectvIfyouknowthisversionpostonPEiDboardh2 {
  strings:
    $a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}

rule _PEiDBundle_v102__v104__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.02 - v1.04 --> BoB / BobSoft"

  strings:
    $0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $0 at pe.entry_point
}

rule _PEiDBundle_v100__v101__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.00 - v1.01 --> BoB / BobSoft"

  strings:
    $0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

  condition:
    $0 at pe.entry_point
}

rule _PEiDBundle_v101__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.01 --> BoB / BobSoft"

  strings:
    $0 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

  condition:
    $0 at pe.entry_point
}

rule _ASProtect_v__If_you_know_this_version_post_on_PEiD_board_h2_ {
  meta:
    description = "ASProtect v?.? -> If you know this version, post on PEiD board (h2)"

  strings:
    $0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $0
}

rule _PEiDBundle_v102__v103_DLL__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.02 - v1.03 DLL --> BoB / BobSoft"

  strings:
    $0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }

  condition:
    $0 at pe.entry_point
}

rule _PEiDBundle_v102__v103__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.02 - v1.03 --> BoB / BobSoft"

  strings:
    $0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $0 at pe.entry_point
}

rule _PEiDBundle_v100__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.00 --> BoB / BobSoft"

  strings:
    $0 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

  condition:
    $0 at pe.entry_point
}

rule _ASProtect_v__If_you_know_this_version_post_on_PEiD_board_ {
  meta:
    description = "ASProtect v?.? -> If you know this version, post on PEiD board"

  strings:
    $0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule Upx_Lock1_0_1_2__CyberDoom_Team_X_BoB_TeamPEiD {
  meta:
    author      = "PEiD"
    description = "Upx-Lock 1.0 - 1.2 -> CyberDoom / Team-X + BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

  condition:
    $a0
}

rule SplashBitmap1_00_WithUnpackCode___BoB_TeamPEiD {
  meta:
    author      = "PEiD"
    description = "Splash Bitmap 1.00 (With Unpack Code) -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }

  condition:
    $a0
}

rule SplashBitmap1_00__BoB_TeamPEiD {
  meta:
    author      = "PEiD"
    description = "Splash Bitmap 1.00 -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }

  condition:
    $a0
}

rule Imploder1_04__BoB_Team_PEiD {
  meta:
    author      = "PEiD"
    description = "Imploder 1.04 -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 60 E8 C8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $a0
}

rule PluginToExe1_00__BoB_Team_PEiD {
  meta:
    author      = "PEiD"
    description = "PluginToExe 1.00 -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }

  condition:
    $a0
}

rule PluginToExe1_01__BoB_Team_PEiD {
  meta:
    author      = "PEiD"
    description = "PluginToExe 1.01 -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }

  condition:
    $a0
}

rule BobPack1_00___BoB_Team_PEiD {
  meta:
    author      = "PEiD"
    description = "BobPack 1.00 --> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 ?? ?? ?? ?? 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 00 00 B8 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 44 24 1C 61 50 31 C0 C3 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 8B }

  condition:
    $a0
}

rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board: PEiD {
  strings:
    $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a at pe.entry_point

}

rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board_h2_additional: PEiD {
  strings:
    $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }

  condition:
    $a at pe.entry_point

}

rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board_h2: PEiD {
  strings:
    $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $b = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
    $c = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

