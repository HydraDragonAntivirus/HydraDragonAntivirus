rule stowaway
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "signature_keyword"

    strings:
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string1 = /HackTool\.Stowaway/ nocase ascii wide

    condition:
        any of them
}
