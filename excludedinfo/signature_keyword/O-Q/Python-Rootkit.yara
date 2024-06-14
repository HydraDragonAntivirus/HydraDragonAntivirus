rule Python_Rootkit
{
    meta:
        description = "Detection patterns for the tool 'Python-Rootkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Python-Rootkit"
        rule_category = "signature_keyword"

    strings:
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string1 = /HackTool\:Python\/LaZagne\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}
