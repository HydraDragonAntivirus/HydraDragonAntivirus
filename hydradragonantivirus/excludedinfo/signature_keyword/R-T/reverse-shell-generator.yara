rule reverse_shell_generator
{
    meta:
        description = "Detection patterns for the tool 'reverse-shell-generator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-shell-generator"
        rule_category = "signature_keyword"

    strings:
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string1 = /Trojan\:PowerShell\/ReverseShell\./ nocase ascii wide

    condition:
        any of them
}
