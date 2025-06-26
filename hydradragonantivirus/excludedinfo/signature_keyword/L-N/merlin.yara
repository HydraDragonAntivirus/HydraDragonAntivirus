rule merlin
{
    meta:
        description = "Detection patterns for the tool 'merlin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin"
        rule_category = "signature_keyword"

    strings:
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string1 = /Trojan\:Win32\/TrickbotCrypt/ nocase ascii wide

    condition:
        any of them
}
