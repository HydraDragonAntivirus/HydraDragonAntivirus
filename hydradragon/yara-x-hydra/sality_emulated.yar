import "pe"
import "hydra"

rule Win32_Sality_Emulated {
    meta:
        description = "Detects Sality using Hydra native emulation and PE features"
        author = "HydraDragon"
        malware_family = "Win32.Sality"
    
    condition:
        // 1. Must be a valid PE file
        pe.is_pe and
        
        // 2. DLLs commonly seen in Sality droppers (especially those packed with WiX Toolset)
        pe.imports("cabinet.dll") and
        pe.imports("crypt32.dll") and
        pe.imports("wininet.dll") and
        
        // 3. Section check specific to Sality droppers
        for any section in pe.sections : (
            section.name == ".wixburn"
        ) and
        
        // --- HYDRA NATIVE TELEMETRY (Newly Added ML & Emulation Features) ---
        
        // 4. Ensures the Hydra Unicorn Engine successfully executed 256 instructions from the Entry Point
        hydra.pe.emulation.executed_instructions == 256 and
        
        // 5. Detects if the emulated machine code attempted to allocate memory or inject itself
        for any api in hydra.pe.emulation.executed_apis : (
            api == "VirtualAlloc"
        )
}
