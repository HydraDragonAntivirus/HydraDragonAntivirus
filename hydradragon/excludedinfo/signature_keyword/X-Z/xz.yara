rule xz
{
    meta:
        description = "Detection patterns for the tool 'xz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xz"
        rule_category = "signature_keyword"

    strings:
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string1 = /HEUR\:Trojan\.Script\.XZ/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string2 = /MEM\:Trojan\.Linux\.XZ/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string3 = /Trojan\.Shell\.XZ/ nocase ascii wide

    condition:
        any of them
}
