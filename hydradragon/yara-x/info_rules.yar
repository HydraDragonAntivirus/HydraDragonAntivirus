// --- moved from clean_rules.yar ---
rule INFO_API_OVERRIDE_TOOL_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of renamed section name added by API Override tool"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".winapi"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_ASPACK_PACKER {
  meta:
    version      = "1"
    date         = "1/5/24"
    modified     = "1/5/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of ASPACK Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "b456385b1e0cb6c85066b7618e52758a"
    hash         = "9ff07edb51a737e4a314cc0e495788b8c7b8d02c"
    hash         = "866028bad1dd43edb256416a71896584e02294cba419dd508a8a2afc81ac5ebc"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".aspack" or
        pe.sections[i].name == ".adata" or
        pe.sections[i].name == "ASPack" or
        pe.sections[i].name == ".ASPack"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_BOOMERANG_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Boomerang List Builder renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".boom"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_CCG_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of CCG Packer (Chinese Packer) renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".ccg"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_CRUNCH_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Crunch 2.0 Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "22c4b235e0de288617767567125706bf"
    hash         = "3bd508a7733e22bba1c49f0934317d11b9e34ad4"
    hash         = "94f3b1421488727995d368fb32909f0a0b04e447ba33075c98592e769db78595"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "BitArts"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_DAStub_Dragon_Armor_protector {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of DAStub Dragon Armor protector renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "DAStub"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_ENIGMA_PROTECTOR {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Enigma Protector renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "5b23d6b5fb0b7195231ec24d5861ef71"
    hash         = "6b60c43b3e0e9e56d7b378821ba497ed154f3195"
    hash         = "afefa95de9d2a7f8f78b2d07edb791f04cae8910e32925167a015508ece2d790"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".enigma1" or
        pe.sections[i].name == ".enigma2"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_EPACK_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Epack packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "5c6078d30b23cc15da0c7db7adcab4b1"
    hash         = "7412d67f7501c51535127438eadf27ae03610549"
    hash         = "782198d1eda4866e04ce625424176a0d924ef78ab7dbf7351c129e71f36a3eb4"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "!EPack"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_FIRSERIA_PUP_DOWNLOADER_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Firseria PUP downloaders renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".mnbvcx1" or
        pe.sections[i].name == ".mnbvcx2"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_GENTEE_INSTALLER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Gentee Installer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "ccefb390d79166a577fc3daf036e902d"
    hash         = "11ef5788819e03e9f74ec059261f2a16c3da7d58"
    hash         = "a35539d69fce5105782aade3ec061c49d1ecab5e2961e491de87f10802d3da79"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".gentee"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_ImpRec_Section_name {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of ImpRec created section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "434c3add35ae58605c17dde7cf4c72a4"
    hash         = "abe91cb89d2e9d948c912f941cfb2fdf11c0ff4d"
    hash         = "509aa1cb0581be5a930b2d03865680bc6060fbe1e5479aa464553e2adcf0c3ee"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".mackt"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_KCP_MZ_FILE {
  meta:
    version      = "1"
    date         = "1/17/24"
    modified     = "1/17/24"
    status       = "DEVELOPMENT"
    sharing      = "TLP:CLEAR"
    source       = "https://github.com/skywind3000/kcp/blob/master/ikcp.c"
    author       = "@x0rc1sm"
    description  = "taking print and log reference from KCP, trying to find other implementations"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "N/A"
    hash         = ""
    hash         = ""
    hash         = ""

  strings:
    $kcp1  = "[RO] %ld bytes"  //ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size)
    $kcp2  = "[RI] %d bytes"  //ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
    $kcp3  = "recv sn=%lu"  //ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
    $kcp4  = "input ack: sn=%lu rtt=%ld rto=%ld"  //ikcp_log(kcp, IKCP_LOG_IN_ACK, "input ack: sn=%lu rtt=%ld rto=%ld", (unsigned
    $kcp5  = "input psh: sn=%lu ts=%lu"  //ikcp_log(kcp, IKCP_LOG_IN_DATA, "input psh: sn=%lu ts=%lu", (unsigned long)sn,
    $kcp6  = "input probe"  //ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
    $kcp7  = "input wins: %lu"  //ikcp_log(kcp, IKCP_LOG_IN_WINS, "input wins: %lu", (unsigned long)(wnd));
    $kcp8  = "snd(buf=%d, queue=%d)\\n"  // printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
    $kcp9  = "rcv(buf=%d, queue=%d)\\n"  // printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
    $kcp10 = "rcv_nxt=%lu\\n"  // printf("rcv_nxt=%lu\n"
    $kcp11 = "rcvbuf"  //ikcp_qprint("rcvbuf"

  condition:
    uint16(0) == 0x5a4d and 5 of them
}


// --- moved from clean_rules.yar ---
rule INFO_KKRUNCHY_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of kkrunchy packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "e2f4598f958cf3647dec16c5d09fb9ae"
    hash         = "cb817a994afd5fc552907bfc012e05f814fed4fe"
    hash         = "3dd4bfa875061d222e57ae998041b1e22347a226cde106666e2a7a11d642b260"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "kkrunchy"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_MASKPE_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of MaskPE Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".MaskPE"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_MEW_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of MEW packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "MEW"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_NEOLITE_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Neolite Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "6a46ce5d22772e496a82755d235f5e3f"
    hash         = "fe01b8cd0c53d390252097f1bf80ae2d3ca5ee67"
    hash         = "589fa885e561d591ed908dc39459997e78699d7a2efb4d5b49bc658ced378f9e"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".neolite" or
        pe.sections[i].name == ".neolit"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_NIGHTHAWK_C2_FRAMEWORK_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of NightHawk C2 framework (by MDSec) renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".profile"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_NSPACK_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of NSPACK Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "ec7a1955e6a826d407b225111c1a384d"
    hash         = "9310d50074d488797703f8b4ab6229a74e7c2127"
    hash         = "f71d3c3db66f57a13924571d50c6816f8bf515327e57267782911ba446b5b3eb"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".nsp0" or
        pe.sections[i].name == ".nsp1" or
        pe.sections[i].name == ".nsp2" or
        pe.sections[i].name == "nsp0" or
        pe.sections[i].name == "nsp1" or
        pe.sections[i].name == "nsp2"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PEBUNDLE_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of PEBundle Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "6f1dfd1d01d868bdce1566e4593a5a36"
    hash         = "f77dee085637e35ab8f8240f1169a8ae67d95fdb"
    hash         = "481966d0c2f96a1c74b1f7e46aa4b040087cb38307f737dc15563a44bd64f0ad"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "pebundle" or
        pe.sections[i].name == "PEBundle"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PECOMPACT_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of PECompact Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "efc913c43be24b76da3cf878552bf689"
    hash         = "2bcd7b067784a3317f1dfbfd3e0ab1901399410d"
    hash         = "43111606af74d300f30bf6de21e01694047f236b3c57d79ee2cc5025dbeec929"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "PEC2TO" or
        pe.sections[i].name == "PEC2MO" or
        pe.sections[i].name == "PEC2" or
        pe.sections[i].name == "pec" or
        pe.sections[i].name == "pec1" or
        pe.sections[i].name == "pec2" or
        pe.sections[i].name == "pec3" or
        pe.sections[i].name == "pec4" or
        pe.sections[i].name == "pec5" or
        pe.sections[i].name == "pec6"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PELOCK_PROTECTOR {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of PELock Protector renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "ea86363d5c9688b9d3d32d94e5d49b92"
    hash         = "010faf66635243e7f4d337ecc397bfa9db9ce60f"
    hash         = "2d8e22c485c4e7ff511c7dae1b4e186d5ec5e2af29e12372d8403b03867c6723"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "PELOCKnt"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PERPLEX_PROTECTOR {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Perplex PE-Protector renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "e9a2ce9fa89941ed4aa90a0b1fda071e"
    hash         = "bc7bffb6b577b2876c760984b03cb2568e918c42"
    hash         = "a6b85778185e469b23e0da8d76f7c9019e2c24463d0a52b96b554aaaf2695462"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".perplex"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PESHIELD_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of PEShield Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "PESHiELD"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PESPIN_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Some version os PESpin renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "30633847385092004d786595e69c33dd"
    hash         = "fbaad9d6b0975c7e16bc0dc65a0f349935e58596"
    hash         = "6592c0c6b8ce359c1f642d9d8bc2014fd7d2c276e602f48233b38a275d127e60"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".taz"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PETITE_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Petite Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "e3048c234c314bd06c60e128216b8578"
    hash         = "f9dff7b1d0aaf208ddd1061a22b9ed921118904c"
    hash         = "b23f3b7e4f8e97e597da88a9638a3474df7eee5ad2a627b6caf0ef11657c1e1c"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".petite"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PHP_BASE64_EVAL {
  meta:
    version        = "1"
    date           = "1/19/24"
    modified       = "1/19/24"
    status         = "RELEASED"
    sharing        = "TLP:CLEAR"
    source         = "n/a"
    author         = "@x0rc1sm"
    description    = "Trying to find base64 obfuscation in PHP files"
    category       = "INFO"
    malware_type   = "N/A"
    malware_family = "N/A"
    mitre_att      = "N/A"
    actor_type     = "N/A"
    actor          = "N/A"
    report         = "https://www.youtube.com/watch?v=BnmVXJQAQu8"
    hash           = "6459a462e3511f016266e3e243b1b55d"
    hash           = "3cf3cba9cd54916649774b8ac03715fbb92676d6"
    hash           = "cda07c66b05bbfb85c23a345386bb526a397e7a8265abd083f7f124b08fd532e"

  strings:
    $str1 = "<?php"
    $str2 = /eval\s?\(\s?base64_decode\s?\("[A-Za-z0-9+\/]{0,500}/

  condition:
    $str1 at 0 and filesize < 1MB and $str2
}


// --- moved from clean_rules.yar ---
rule INFO_PIN_TOOL_ARTIFACT {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of PIN Tool renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".pinclie"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_PROCRYPT_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of ProCrypt Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "ProCrypt"
      )
    )
}

// --- moved from clean_rules.yar ---
rule INFO_RLPACK_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of RLPack Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "7baf89a70ac2cd239815c9dd0af7a5a6"
    hash         = "2b133eaf40810da8d40ac4de3b849799c92c5001"
    hash         = "a7a012169519d31fec73db83f628720528c68ce3d5bb462c517c53b8e5f004ba"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".packed" or
        pe.sections[i].name == ".RLPack"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_RPCRYPT_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of RPCrypt Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "RCryptor" or
        pe.sections[i].name == ".RPCryptor"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_SEAUSFX_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of SeauSFX Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".seau"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_SHRINKER_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Shrinker renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "b48ed7a1a8713b20ae04fab1102464a4"
    hash         = "1d08c1ee244d66cf2c908969d5bca2f80b1cb43b"
    hash         = "1f90241469ef61bc3393cbbf0216a7fd2ea95546fc358cb2ed61960fcf0c645b"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".shrink1" or
        pe.sections[i].name == ".shrink2" or
        pe.sections[i].name == ".shrink3"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_SIMPLE_PACK_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Simple Pack (by bagie) renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".spack"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_STARFORCE_PROTECTION_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of StarForce Protection renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "4aaa34a365a1f5751cbc0f3b4139ab32"
    hash         = "4e5b5f786c6970b99a4b5902b21aef7e2db0bbdc"
    hash         = "e58e4b7f670d95ee270c10d53811d1f3f4cd2c642f656d2214d94e45745f9fe9"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".sforce3"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_SVKP_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of SVKP packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".svkp"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_THEMIDA_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Themida Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "ff121cdd62bafa619e2485c397098f7f"
    hash         = "d0b5ad3f3141b4390480f52b456864ffc322e65e"
    hash         = "d0bf3cb889cff503c8cffe2a883f191200506a6ef34db658c7173ee08da68fc3"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "Themida" or
        pe.sections[i].name == ".Themida"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_TSULOADER_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of TSULoader renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "717f2c41817163e959e537d6fcc6e47e"
    hash         = "8f5f5584141f0ac5e8aa44fec10a66b6df96d3a0"
    hash         = "7d403eab8b54213c21fd81950e8e8ba57df5a715251e019869759379202265d5"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".tsuarch" or
        pe.sections[i].name == ".tsustub"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_UNKNOWN_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Unknown Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "7baf89a70ac2cd239815c9dd0af7a5a6"
    hash         = "2b133eaf40810da8d40ac4de3b849799c92c5001"
    hash         = "a7a012169519d31fec73db83f628720528c68ce3d5bb462c517c53b8e5f004ba"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".packed"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_UPACK_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Upack packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "dca1503c73cdd9aef6e771786e5676f0"
    hash         = "531f62a49097b79292e30d79ca2870165bbd5295"
    hash         = "c7afdd5cfd597e820af8c21bdae641ae16ef74c28c4053c87cdd32c779b0da4d"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".Upack" or
        pe.sections[i].name == ".ByDwing"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_VPROTECT_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Vprotect Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "83abc83ac4a8a97de062b56f2518a8b1"
    hash         = "3275e01497b20161067ad36b964ac719898c0094"
    hash         = "99f6d0c080cd05ae1466385b125ccd6744a86c4bae7973441c4147948b8b31e9"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "VProtect"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_WinLicense_Protector {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of WinLicense (Themida) Protector renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "WinLicen"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_WINZIP_SELF_EXTRACTOR_SECTION_NAME {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of renamed section name added by WinZip Self-Extractor"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "32c956ef503b080620e60905d77d2730"
    hash         = "6f7a9d1896d1e454def52bde2f8a05f445b30555"
    hash         = "8afdffe950611d59703520b08904ce23d442defb1875468efd57f4639298f1aa"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "_winzip_"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_WWPACK_PACKER {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of WWPACK and WWPACK32 Packer renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = ""
    hash         = ""
    hash         = ""

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == "WWPACK" or
        pe.sections[i].name == ".WWP32"
      )
    )
}


// --- moved from clean_rules.yar ---
rule INFO_XOR_DOS_HEADER {
  meta:
    version      = "1"
    date         = "1/3/24"
    modified     = "1/3/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of This Program Cannot XOR'd"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "N/A"
    hash         = "1e4f9b61339c3a0b5ca1537913b08662"
    hash         = "d80d41986d3c5f168cb0e55b84e81998a19346d5"
    hash         = "2f114b77d54dee4292a3411da5bd105b59b2b152d91448900c8bb65c33a494b5"

  strings:
    $string = "This program cannot be run in DOS mode" xor(0x01-0xff)

  condition:
    $string in (200..filesize)
}


// --- moved from clean_rules.yar ---
rule INFO_Y0DA_PROTECTOR {
  meta:
    version      = "1"
    date         = "1/6/24"
    modified     = "1/6/24"
    status       = "RELEASED"
    sharing      = "TLP:CLEAR"
    source       = "n/a"
    author       = "@x0rc1sm"
    description  = "Detection of Y0da Protector renamed section names"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
    hash         = "f3dd8e593b91c911556fad99b07dfd1c"
    hash         = "eb9e98484a16f56b58236ba89d8edbaf92ccbbc2"
    hash         = "d8581aeacd0429934eaa279d14a86d473c405d85cd9904237ba0afafbe6ae8f0"

  condition:
    uint16(0) == 0x5a4d and for any i in (0..pe.sections.len()): (
      (
        pe.sections[i].name == ".yP" or
        pe.sections[i].name == ".y0da"
      )
    )
}

