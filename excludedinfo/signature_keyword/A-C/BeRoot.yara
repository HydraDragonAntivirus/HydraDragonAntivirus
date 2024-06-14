rule BeRoot
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "signature_keyword"

    strings:
        // Description: Privilege Escalation Project - Windows / Linux / Mac - signature observed with linux-exploit-suggester.sh 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string1 = /HackTool\:SH\/LinuxExploitSuggest/ nocase ascii wide

    condition:
        any of them
}
