rule wraith
{
    meta:
        description = "Detection patterns for the tool 'wraith' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wraith"
        rule_category = "signature_keyword"

    strings:
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string1 = /VirTool\:Python\/Wraitratz\.A/ nocase ascii wide

    condition:
        any of them
}
