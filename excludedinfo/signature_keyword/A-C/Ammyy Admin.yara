rule Ammyy_Admin
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "signature_keyword"

    strings:
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string1 = /PUA\:Win32\/AmmyyAdmin/ nocase ascii wide

    condition:
        any of them
}
