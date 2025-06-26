rule Amnesiac
{
    meta:
        description = "Detection patterns for the tool 'Amnesiac' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amnesiac"
        rule_category = "signature_keyword"

    strings:
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments - signatureobserved for dpapi.ps1and HiveDump.ps1
        // Reference: https://github.com/Leo4j/Amnesiac
        $string1 = /VirTool\:PowerShell\/Dipadz\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}
