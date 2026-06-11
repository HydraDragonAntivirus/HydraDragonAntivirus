rule XWorm_Loader_TaskScheduler_Trojan {
    meta:
        description = "Detects XWorm .NET loader trojanized as Microsoft.Win32.TaskScheduler.dll with 205 injected malicious namespaces including HackForums.gigajew.Mandark RunPE, VirtualMachineDetector, and CMSTP UAC bypass"
        author = "Lenard-Code"
        date = "2026-03-10"
        malpedia_family = "win.xworm"
        hash = "34e90568af4dcd40f4f04174ec326e2a"
    strings:
        $ns1 = "HackForums.gigajew" ascii
        $ns2 = "Mandark" ascii
        $ns3 = "VirtualMachineDetector" ascii
        $s1 = "Bypass executado com sucesso!" wide
        $s2 = "Erro ao executar o bypass." wide
        $s3 = "Baixar e executar o PuTTY" wide
        $s4 = "52:54:00:4A:04:AF" wide
        $s5 = "CorpVPN" wide
        $s6 = "conhost.exe" wide
        $s7 = "EnableLUA" wide
        $pdb = "Microsoft.Win32.TaskScheduler.pdb" ascii
        $api1 = "ZwUnmapViewOfSection" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            ($ns1 and $ns2) or
            ($ns3 and 1 of ($api*)) or
            (3 of ($s*)) or
            ($pdb and 2 of ($api*))
        )
}