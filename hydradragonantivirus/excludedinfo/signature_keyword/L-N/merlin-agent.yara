rule merlin_agent
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent"
        rule_category = "signature_keyword"

    strings:
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string1 = /A\sVariant\sOf\sWinGo\/Merlin\.A/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string2 = /W64\/Merlin\.T\!tr/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string3 = /Win64\:MerlinAgent/ nocase ascii wide

    condition:
        any of them
}
