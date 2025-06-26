rule kiglogger
{
    meta:
        description = "Detection patterns for the tool 'kiglogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kiglogger"
        rule_category = "signature_keyword"

    strings:
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string1 = /Win32\/KidLogger/ nocase ascii wide

    condition:
        any of them
}
