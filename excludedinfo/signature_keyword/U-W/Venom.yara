rule Venom
{
    meta:
        description = "Detection patterns for the tool 'Venom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Venom"
        rule_category = "signature_keyword"

    strings:
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string1 = /Trojan\:Win32\/Casdet\!rfn/ nocase ascii wide

    condition:
        any of them
}
