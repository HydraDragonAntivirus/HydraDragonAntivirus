rule PEASS
{
    meta:
        description = "Detection patterns for the tool 'PEASS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS"
        rule_category = "signature_keyword"

    strings:
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string1 = /VirTool\:MSIL\/Aikaantivm\.GG\!MTB/ nocase ascii wide

    condition:
        any of them
}
