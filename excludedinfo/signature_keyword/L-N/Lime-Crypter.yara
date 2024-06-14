rule Lime_Crypter
{
    meta:
        description = "Detection patterns for the tool 'Lime-Crypter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lime-Crypter"
        rule_category = "signature_keyword"

    strings:
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string1 = /Ransom\:Win32\/Sodinokibi/ nocase ascii wide

    condition:
        any of them
}
