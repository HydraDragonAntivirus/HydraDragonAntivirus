rule SharpEDRChecker
{
    meta:
        description = "Detection patterns for the tool 'SharpEDRChecker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEDRChecker"
        rule_category = "signature_keyword"

    strings:
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string1 = /VirTool\:MSIL\/Kanuko\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}
