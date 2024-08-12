rule RLO_and_EncryptedZip {
    meta:
        description = "Detects files with RLO characters before a period and encrypted ZIP files, including files within subfolders"
        author = "Emirhan Ucan"
        date = "2024-08-12"
        reference = "https://www.virustotal.com/gui/file/9d10b30936a63cfee70fddbe04494ff06a9a15ded043ce69cdcc32205f6273a1"
    
    strings:
        // Detect the RLO character
        $rlo_character = { E2 80 AE }

        // Detect a period (.)
        $period = { 2E }

        // ZIP magic number (indicates the start of a ZIP file)
        $zip_magic = { 50 4B 03 04 }

        // Regular expression to match RLO character before a period
        $rlo_before_period = /[\xE2\x80\xAE][^\x2E]*\x2E/

    condition:
        // Check if the file is a ZIP archive
        $zip_magic at 0
        and
        // Iterate over Central Directory entries to check for encrypted files
        for any i in (0..filesize - 4) : (
            // Look for the Central Directory File Header signature
            uint32be(i) == 0x504b0102
            and (
                // Check if the file is encrypted (bit 0 of general-purpose flag is set)
                uint16(i + 8) & 1 == 1
                or
                // Check for specific encryption methods in the compression method field
                uint16(i + 10) == 0x01 // Store
                or uint16(i + 10) == 0x09 // Deflate
                or uint16(i + 10) == 0x14 // LZMA
                or uint16(i + 10) == 0x63 // LZMA2
                or uint16(i + 10) == 0x99 // AES
            )
        )
        and
        // Ensure the RLO character appears before any period (.)
        $rlo_before_period
        and
        // Optionally use the $rlo_character string directly
        $rlo_character
        and
        // Optionally use the $period string directly
        $period
}

rule RLO_After_Comma {
    meta:
        description = "Detects the RLO (Right-to-Left Override) character when it appears after a comma"
        author = "Emirhan Ucan"
        date = "2024-08-12"
        reference = "https://www.virustotal.com/gui/file/9d10b30936a63cfee70fddbe04494ff06a9a15ded043ce69cdcc32205f6273a1"
    
    strings:
        // Detect the RLO character following a comma
        $rlo_after_comma = /[\x2C][\xE2\x80\xAE]/

    condition:
        // Trigger if the RLO character appears after a comma
        $rlo_after_comma
}