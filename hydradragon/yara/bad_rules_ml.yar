/*
   YARA Rule Set
   Author: HydraDragonAntivirus
   Date: 2026-03-24
   Identifier: datamaliciousorder
   Reference: https://github.com/HydraDragonAntivirus
   License: AGPLv3
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_4_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_4_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "68c20c6a5e67c70a346a1437115dfc8665f1db9694bede7b8a298d0747707649"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 60 60 ff 34 24 8d 64 24 44 0f 82 80 39 03 00 e9 }
      $op1 = { c1 65 e8 08 c1 65 e4 08 50 ac c0 c8 05 34 81 fe }
      $op2 = { e8 38 f0 ff ff 83 e9 01 0f 85 d9 ff ff ff c3 f5 }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}

rule Virus_Infector_Win32_Expiro_Gen_7_23_1 {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_23_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "e134018e4da8707607e30d39f1d8351b53d6c3873f07d8fd02f891cdafd0b3ba"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 01 00 30 00 34 00 31 00 39 00 30 00 34 00 42 00 }
      $op1 = { 20 04 35 04 34 04 30 04 3a 04 42 04 3e 04 40 04 }
      $op2 = { f9 73 2c c3 c1 d0 01 33 c7 f5 8b 34 24 58 81 ee }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}

rule Virus_Infector_Win32_Expiro_Gen_7_24_1 {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_24_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "92b6dd1c9b21793341a7cb1d87b3a553566dfee7ee14fe7db6e48e5d6d741074"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 01 00 30 00 34 00 31 00 39 00 30 00 34 00 42 00 }
      $op1 = { 20 04 35 04 34 04 30 04 3a 04 42 04 3e 04 40 04 }
      $op2 = { f9 73 2c c3 c1 d0 01 33 c7 f5 8b 34 24 58 81 ee }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}

rule Virus_Infector_Win32_Expiro_Gen_7_25_1 {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_25_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "5ecbc947f2853fe9a3479e523b5ddfeaec9c2ca98a08e894e9c6652c5132e62e"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 01 00 30 00 34 00 31 00 39 00 30 00 34 00 42 00 }
      $op1 = { 20 04 35 04 34 04 30 04 3a 04 42 04 3e 04 40 04 }
      $op2 = { f9 73 2c c3 c1 d0 01 33 c7 f5 8b 34 24 58 81 ee }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}

rule Virus_Infector_Win32_Expiro_Gen_7_26_1 {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_26_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "d300ff194e7b16fc97b976c0e0c4b7ed6f1ff70044657b437b171338261a2910"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 01 00 30 00 34 00 31 00 39 00 30 00 34 00 42 00 }
      $op1 = { 20 04 35 04 34 04 30 04 3a 04 42 04 3e 04 40 04 }
      $op2 = { f9 73 2c c3 c1 d0 01 33 c7 f5 8b 34 24 58 81 ee }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}