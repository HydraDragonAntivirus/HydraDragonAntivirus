// 11 false-positive rule(s) removed by false_positive_remover.py

rule cred_ff {
  meta:
    author      = "x0r"
    description = "Steal Firefox credential"
    version     = "0.1"

  strings:
    $f1 = "signons.sqlite"
    $f2 = "signons3.txt"
    $f3 = "secmod.db"
    $f4 = "cert8.db"
    $f5 = "key3.db"

  condition:
    any of them
}

rule BobSoftMiniDelphiBoBBobSoft {
  strings:
    $a0 = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }
    $a1 = { 55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8 }
    $a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }

  condition:
    $a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
}

rule shellcode_at_entry_point {
  meta:
    author      = "nex"
    description = "Matched shellcode byte patterns"
    modified    = "Glenn Edwards (@hiddenillusion)"

  condition:
    uint16be(pe.entry_point) == 0x648b and uint8(pe.entry_point + 2) == 0x64 or
    uint16be(pe.entry_point) == 0x64a1 and uint8(pe.entry_point + 2) == 0x30 or
    uint32be(pe.entry_point) == 0x648b1530 or
    uint32be(pe.entry_point) == 0x648b3530 or
    uint32be(pe.entry_point) == 0x558bec83 and uint8(pe.entry_point + 4) == 0xc4 or
    uint32be(pe.entry_point) == 0x558bec81 and uint8(pe.entry_point + 4) == 0xec or
    uint32be(pe.entry_point) == 0x558bece8 or
    uint32be(pe.entry_point) == 0x558bece9
}

rule _BobSoft_Mini_Delphi__BoB__BobSoft_ {
  meta:
    description = "BobSoft Mini Delphi -> BoB / BobSoft"

  strings:
    $0 = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }
    $1 = { 55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8 }
    $2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule BobSoft_Mini_Delphi_BoB_BobSoft_additional: PEiD {
  strings:
    $a = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }

  condition:
    $a at pe.entry_point

}

rule _DangerousPhp {
  strings:
    $system = "system" fullword nocase  // localroot bruteforcers have a lot of this

    $ = "array_filter" fullword nocase
    $ = "assert" fullword nocase
    $ = "backticks" fullword nocase
    $ = "call_user_func" fullword nocase
    $ = "eval" fullword nocase
    $ = "exec" fullword nocase
    $ = "fpassthru" fullword nocase
    $ = "fsockopen" fullword nocase
    $ = "function_exists" fullword nocase
    $ = "getmygid" fullword nocase
    $ = "shmop_open" fullword nocase
    $ = "mb_ereg_replace_callback" fullword nocase
    $ = "passthru" fullword nocase
    $ = /pcntl_(exec|fork)/ fullword nocase
    $ = "php_uname" fullword nocase
    $ = "phpinfo" fullword nocase
    $ = "posix_geteuid" fullword nocase
    $ = "posix_getgid" fullword nocase
    $ = "posix_getpgid" fullword nocase
    $ = "posix_getppid" fullword nocase
    $ = "posix_getpwnam" fullword nocase
    $ = "posix_getpwuid" fullword nocase
    $ = "posix_getsid" fullword nocase
    $ = "posix_getuid" fullword nocase
    $ = "posix_kill" fullword nocase
    $ = "posix_setegid" fullword nocase
    $ = "posix_seteuid" fullword nocase
    $ = "posix_setgid" fullword nocase
    $ = "posix_setpgid" fullword nocase
    $ = "posix_setsid" fullword nocase
    $ = "posix_setsid" fullword nocase
    $ = "posix_setuid" fullword nocase
    $ = "preg_replace_callback" fullword
    $ = "proc_open" fullword nocase
    $ = "proc_close" fullword nocase
    $ = "popen" fullword nocase
    $ = "register_shutdown_function" fullword nocase
    $ = "register_tick_function" fullword nocase
    $ = "shell_exec" fullword nocase
    $ = "shm_open" fullword nocase
    $ = "show_source" fullword nocase
    $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
    $ = "stream_socket_pair" nocase
    $ = "suhosin.executor.func.blacklist" nocase
    $ = "unregister_tick_function" fullword nocase
    $ = "win32_create_service" fullword nocase
    $ = "xmlrpc_decode" fullword nocase
    $ = /ob_start\s*\(\s*[^\)]/  //ob_start('assert'); echo $_REQUEST['pass']; ob_end_flush();

    $whitelist = /escapeshellcmd|escapeshellarg/ nocase

  condition:
    (not $whitelist and (5 of them or #system > 250)) and not IsWhitelisted
}

rule libavcodec_ff_mpa_enwindow__32_lil_1028_ {
  strings:
    $a0 = { 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE FF FF FF FE FF FF FF FE FF FF FF FE FF FF FF FD FF FF FF FD FF FF FF FC FF FF FF FC FF FF FF FB FF FF FF FB FF FF FF FA FF FF FF F9 FF FF FF F9 FF FF FF F8 FF FF FF F7 FF FF FF F6 FF FF FF F5 FF FF FF F3 FF FF FF F2 FF FF FF F0 FF FF FF EF FF FF FF ED FF FF FF EB FF FF FF E8 FF FF FF E6 FF FF FF E3 FF FF FF E1 FF FF FF DD FF FF FF DA FF FF FF D7 FF FF FF D3 FF FF FF CF FF FF FF CB FF FF FF C6 FF FF FF C1 FF FF FF BC FF FF FF B7 FF FF FF B1 FF FF FF AB FF FF FF A5 FF FF FF 9F FF FF FF 98 FF FF FF 91 FF FF FF 8B FF FF FF 83 FF FF FF 7C FF FF FF 75 FF FF FF 6D FF FF FF 66 FF FF FF 5F FF FF FF 57 FF FF FF 50 FF FF FF 49 FF FF FF 42 FF FF FF 3C FF FF FF 36 FF FF FF 30 FF FF FF D5 00 00 00 DA 00 00 00 DE 00 00 00 E1 00 00 00 E3 00 00 00 E4 00 00 00 E4 00 00 00 E3 00 00 00 E0 00 00 00 DD 00 00 00 D7 00 00 00 D0 00 00 00 C8 00 00 00 BD 00 00 00 B1 00 00 00 A3 00 00 00 92 00 00 00 7F 00 00 00 6A 00 00 00 53 00 00 00 39 00 00 00 1D 00 00 00 FE FF FF FF DC FF FF FF B8 FF FF FF 91 FF FF FF 67 FF FF FF 3B FF FF FF 0C FF FF FF DA FE FF FF A5 FE FF FF 6F FE FF FF 35 FE FF FF F9 FD FF FF BB FD FF FF 7B FD FF FF 39 FD FF FF F5 FC FF FF B0 FC FF FF 69 FC FF FF 21 FC FF FF D8 FB FF FF 8F FB FF FF 46 FB FF FF FD FA FF FF B4 FA FF FF 6C FA FF FF 26 FA FF FF E1 F9 FF FF 9E F9 FF FF 5E F9 FF FF 21 F9 FF FF E7 F8 FF FF B2 F8 FF FF 81 F8 FF FF 56 F8 FF FF 2F F8 FF FF 10 F8 FF FF F7 F7 FF FF E5 F7 FF FF DB F7 FF FF D9 F7 FF FF E0 F7 FF FF F1 F7 FF FF F5 07 00 00 D0 07 00 00 A0 07 00 00 65 07 00 00 1E 07 00 00 CB 06 00 00 6C 06 00 00 FF 05 00 00 86 05 00 00 00 05 00 00 6B 04 00 00 CA 03 00 00 1A 03 00 00 5D 02 00 00 92 01 00 00 B9 00 00 00 D3 FF FF FF E0 FE FF FF DF FD FF FF D2 FC FF FF B9 FB FF FF 94 FA FF FF 64 F9 FF FF 2A F8 FF FF E6 F6 FF FF 99 F5 FF FF 44 F4 FF FF E9 F2 FF FF 87 F1 FF FF 21 F0 FF FF B7 EE FF FF 4C ED FF FF DF EB FF FF 73 EA FF FF 09 E9 FF FF A3 E7 FF FF 43 E6 FF FF E9 E4 FF FF 99 E3 FF FF 53 E2 FF FF 1A E1 FF FF EF DF FF FF D5 DE FF FF CD DD FF FF DA DC FF FF FD DB FF FF 38 DB FF FF 8F DA FF FF 01 DA FF FF 92 D9 FF FF 44 D9 FF FF 19 D9 FF FF 12 D9 FF FF 31 D9 FF FF 79 D9 FF FF EA D9 FF FF 88 DA FF FF 53 DB FF FF 4D DC FF FF 78 DD FF FF D4 DE FF FF 64 E0 FF FF 28 E2 FF FF 22 E4 FF FF AE 19 00 00 47 17 00 00 A8 14 00 00 D1 11 00 00 C0 0E 00 00 77 0B 00 00 F5 07 00 00 3A 04 00 00 46 00 00 00 1A FC FF FF B6 F7 FF FF 1C F3 FF FF 4B EE FF FF 46 E9 FF FF 0E E4 FF FF A4 DE FF FF 09 D9 FF FF 41 D3 FF FF 4C CD FF FF 2C C7 FF FF E5 C0 FF FF 79 BA FF FF EA B3 FF FF 3B AD FF FF 6F A6 FF FF 8A 9F FF FF 8E 98 FF FF 7F 91 FF FF 60 8A FF FF 35 83 FF FF 01 7C FF FF C8 74 FF FF 8F 6D FF FF 58 66 FF FF 28 5F FF FF 02 58 FF FF EB 50 FF FF E7 49 FF FF FA 42 FF FF 27 3C FF FF 73 35 FF FF E2 2E FF FF 76 28 FF FF 36 22 FF FF 23 1C FF FF 42 16 FF FF 97 10 FF FF 24 0B FF FF ED 05 FF FF F6 00 FF FF 42 FC FE FF D3 F7 FE FF AC F3 FE FF D1 EF FE FF 42 EC FE FF 04 E9 FE FF 17 E6 FE FF 7D E3 FE FF 39 E1 FE FF 4C DF FE FF B7 DD FE FF 7A DC FE FF 98 DB FE FF 10 DB FE FF 1E 25 01 00 }

  condition:
    $a0
}

rule Noekeon_Nessie_round__32_big_68_ {
  strings:
    $a0 = { 00 00 00 80 00 00 00 1b 00 00 00 36 00 00 00 6c 00 00 00 d8 00 00 00 ab 00 00 00 4d 00 00 00 9a 00 00 00 2f 00 00 00 5e 00 00 00 bc 00 00 00 63 00 00 00 c6 00 00 00 97 00 00 00 35 00 00 00 6a 00 00 00 d4 }

  condition:
    $a0
}

rule Noekeon_Nessie_round__32_lil_68_ {
  strings:
    $a0 = { 80 00 00 00 1b 00 00 00 36 00 00 00 6c 00 00 00 d8 00 00 00 ab 00 00 00 4d 00 00 00 9a 00 00 00 2f 00 00 00 5e 00 00 00 bc 00 00 00 63 00 00 00 c6 00 00 00 97 00 00 00 35 00 00 00 6a 00 00 00 d4 00 00 00 }

  condition:
    $a0
}

rule libavcodec_libmp3lame_sBitRates__16_lil_180_ {
  strings:
    $a0 = { 00 00 20 00 40 00 60 00 80 00 a0 00 c0 00 e0 00 00 01 20 01 40 01 60 01 80 01 a0 01 c0 01 00 00 20 00 30 00 38 00 40 00 50 00 60 00 70 00 80 00 a0 00 c0 00 e0 00 00 01 40 01 80 01 00 00 20 00 28 00 30 00 38 00 40 00 50 00 60 00 70 00 80 00 a0 00 c0 00 e0 00 00 01 40 01 00 00 20 00 30 00 38 00 40 00 50 00 60 00 70 00 80 00 90 00 a0 00 b0 00 c0 00 e0 00 00 01 00 00 08 00 10 00 18 00 20 00 28 00 30 00 38 00 40 00 50 00 60 00 70 00 80 00 90 00 a0 00 00 00 08 00 10 00 18 00 20 00 28 00 30 00 38 00 40 00 50 00 60 00 70 00 80 00 90 00 a0 00 }

  condition:
    $a0
}

rule libavcodec_inverse_table__32_lil_1024_ {
  strings:
    $a0 = { 00 00 00 00 ff ff ff ff 00 00 00 80 56 55 55 55 00 00 00 40 34 33 33 33 ab aa aa 2a 25 49 92 24 00 00 00 20 1d c7 71 1c 9a 99 99 19 75 d1 45 17 56 55 55 15 14 3b b1 13 93 24 49 12 12 11 11 11 00 00 00 10 10 0f 0f 0f 8f e3 38 0e 5f 43 79 0d cd cc cc 0c 0d c3 30 0c bb e8 a2 0b 2d 64 21 0b ab aa aa 0a a4 70 3d 0a 8a 9d d8 09 5f 42 7b 09 4a 92 24 09 b1 dc d3 08 89 88 88 08 85 10 42 08 00 00 00 08 7d f0 c1 07 88 87 87 07 08 75 50 07 c8 71 1c 07 46 3e eb 06 b0 a1 bc 06 07 69 90 06 67 66 66 06 64 70 3e 06 87 61 18 06 d1 17 f4 05 5e 74 d1 05 06 5b b0 05 17 b2 90 05 0b 62 72 05 56 55 55 05 2a 78 39 05 52 b8 1e 05 06 05 05 05 c5 4e ec 04 3f 87 d4 04 30 a1 bd 04 4b 90 a7 04 25 49 92 04 20 c1 7d 04 59 ee 69 04 98 c7 56 04 45 44 44 04 54 5c 32 04 43 08 21 04 05 41 10 04 00 00 00 04 04 3f f0 03 3f f8 e0 03 36 26 d2 03 c4 c3 c3 03 0f cc b5 03 84 3a a8 03 d2 0a 9b 03 e4 38 8e 03 e1 c0 81 03 23 9f 75 03 37 d0 69 03 d8 50 5e 03 ed 1d 53 03 84 34 48 03 d3 91 3d 03 34 33 33 03 20 16 29 03 32 38 1f 03 22 97 15 03 c4 30 0c 03 04 03 03 03 e9 0b fa 02 91 49 f1 02 2f ba e8 02 0c 5c e0 02 83 2d d8 02 03 2d d0 02 0c 59 c8 02 2d b0 c0 02 06 31 b9 02 47 da b1 02 ab aa aa 02 fe a0 a3 02 15 bc 9c 02 d5 fa 95 02 29 5c 8f 02 0d df 88 02 83 82 82 02 98 45 7c 02 63 27 76 02 03 27 70 02 a0 43 6a 02 6a 7c 64 02 98 d0 5e 02 6a 3f 59 02 26 c8 53 02 18 6a 4e 02 93 24 49 02 f1 f6 43 02 90 e0 3e 02 d6 e0 39 02 2d f7 34 02 03 23 30 02 cc 63 2b 02 03 b9 26 02 23 22 22 02 ae 9e 1d 02 2a 2e 19 02 22 d0 14 02 22 84 10 02 bb 49 0c 02 83 20 08 02 11 08 04 02 00 00 00 02 f1 07 fc 01 82 1f f8 01 5a 46 f4 01 20 7c f0 01 7c c0 ec 01 1b 13 e9 01 ad 73 e5 01 e2 e1 e1 01 6f 5d de 01 08 e6 da 01 66 7b d7 01 42 1d d4 01 59 cb d0 01 69 85 cd 01 31 4b ca 01 72 1c c7 01 f1 f8 c3 01 71 e0 c0 01 b9 d2 bd 01 92 cf ba 01 c4 d6 b7 01 1c e8 b4 01 65 03 b2 01 6c 28 af 01 02 57 ac 01 f7 8e a9 01 1b d0 a6 01 42 1a a4 01 40 6d a1 01 ea c8 9e 01 15 2d 9c 01 9a 99 99 01 50 0e 97 01 10 8b 94 01 b5 0f 92 01 19 9c 8f 01 19 30 8d 01 91 cb 8a 01 60 6e 88 01 62 18 86 01 78 c9 83 01 82 81 81 01 60 40 7f 01 f5 05 7d 01 21 d2 7a 01 c9 a4 78 01 cf 7d 76 01 18 5d 74 01 88 42 72 01 06 2e 70 01 77 1f 6e 01 c2 16 6c 01 ce 13 6a 01 82 16 68 01 c7 1e 66 01 86 2c 64 01 a8 3f 62 01 17 58 60 01 bc 75 5e 01 83 98 5c 01 57 c0 5a 01 24 ed 58 01 d4 1e 57 01 56 55 55 01 95 90 53 01 7f d0 51 01 02 15 50 01 0b 5e 4e 01 89 ab 4c 01 6b fd 4a 01 9f 53 49 01 15 ae 47 01 bd 0c 46 01 87 6f 44 01 63 d6 42 01 42 41 41 01 14 b0 3f 01 cc 22 3e 01 5b 99 3c 01 b2 13 3b 01 c3 91 39 01 82 13 38 01 e0 98 36 01 d0 21 35 01 46 ae 33 01 35 3e 32 01 91 d1 30 01 4c 68 2f 01 5d 02 2e 01 b5 9f 2c 01 4b 40 2b 01 13 e4 29 01 02 8b 28 01 0c 35 27 01 28 e2 25 01 4a 92 24 01 68 45 23 01 79 fb 21 01 71 b4 20 01 48 70 1f 01 f4 2e 1e 01 6b f0 1c 01 a5 b4 1b 01 97 7b 1a 01 39 45 19 01 82 11 18 01 69 e0 16 01 e6 b1 15 01 f1 85 14 01 82 5c 13 01 8f 35 12 01 12 11 11 01 02 ef 0f 01 57 cf 0e 01 0b b2 0d 01 15 97 0c 01 6f 7e 0b 01 11 68 0a 01 f4 53 09 01 11 42 08 01 61 32 07 01 de 24 06 01 80 19 05 01 42 10 04 01 1c 09 03 01 09 04 02 01 02 01 01 01 }

  condition:
    $a0
}
