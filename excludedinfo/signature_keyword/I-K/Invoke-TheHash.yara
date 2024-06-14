rule Invoke_TheHash
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "signature_keyword"

    strings:
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side. -signature observed with Invoke-SMBExec.ps1
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string1 = /Trojan\:Win32\/Ceevee/ nocase ascii wide

    condition:
        any of them
}
