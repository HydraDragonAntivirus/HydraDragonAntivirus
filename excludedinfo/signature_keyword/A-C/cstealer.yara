rule cstealer
{
    meta:
        description = "Detection patterns for the tool 'cstealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cstealer"
        rule_category = "signature_keyword"

    strings:
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string1 = /Python\.Stealer/ nocase ascii wide

    condition:
        any of them
}
