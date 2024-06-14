rule AmsiBypass
{
    meta:
        description = "Detection patterns for the tool 'AmsiBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmsiBypass"
        rule_category = "signature_keyword"

    strings:
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string1 = /\/AmsiTamper\./ nocase ascii wide

    condition:
        any of them
}
