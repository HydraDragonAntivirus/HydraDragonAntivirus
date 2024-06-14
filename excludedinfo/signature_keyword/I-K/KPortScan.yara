rule KPortScan
{
    meta:
        description = "Detection patterns for the tool 'KPortScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KPortScan"
        rule_category = "signature_keyword"

    strings:
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string1 = /Win32\/Kportscan/ nocase ascii wide

    condition:
        any of them
}
