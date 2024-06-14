rule merlin_agent_dll
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent-dll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent-dll"
        rule_category = "signature_keyword"

    strings:
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent-dll
        $string1 = /Backdoor\.Merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent-dll
        $string2 = /Win64\:MerlinAgent/ nocase ascii wide

    condition:
        any of them
}
