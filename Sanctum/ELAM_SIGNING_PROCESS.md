# ELAM Signing Process for Sanctum Driver

## Why `sanctum.sys` Cannot Be Committed

The `sanctum.sys` driver file **cannot be committed to the repository** due to the ELAM (Early Launch Anti-Malware) signing requirements. Here's why:

### The Circular Dependency Problem

ELAM drivers require a special signing process that creates a circular dependency:

1. **Generate Certificate** → Create a self-signed ELAM certificate (`sanctum.pfx`)
2. **Build Driver** → Compile the driver with the certificate hash embedded
3. **Sign Driver** → Sign the compiled driver with the certificate
4. **Extract Hash** → Get the "To-Be-Signed Hash" from the signed driver
5. **Update build.rs** → Update the hash in [`build.rs`](build.rs:12) line 12
6. **Rebuild** → Clean and rebuild with the correct hash
7. **Sign Again** → Final signing with matching hash

### Why Each Build Environment Is Different

- Each time [`cert.ps1`](cert.ps1) runs, it generates a **new self-signed certificate** with a **unique hash**
- The hash in [`build.rs`](build.rs:12) must match the certificate's "To-Be-Signed Hash"
- Different build environments (local dev, CI/CD, different machines) = different certificates = different hashes
- Therefore, the compiled `sanctum.sys` is **environment-specific** and cannot be shared

## The Build Process

### Manual Build (Local Development)

Follow the steps in [`readme.md`](readme.md:124-140):

```powershell
# 1. Generate certificate
.\cert.ps1

# 2. Initial build
cargo make

# 3. Sign the driver
.\sign.bat

# 4. Extract the hash
certmgr.exe -v target\debug\sanctum_package\sanctum.sys
# Look for "Content Hash (To-Be-Signed Hash)::" and concatenate the hex bytes

# 5. Update build.rs line 12 with the extracted hash
# Example: L"51DEBDEBFBBF88FECB511184B6A7FEF8EFF005C7C090BB826048CCF988689674\0"

# 6. Clean and rebuild
cargo clean
cargo make

# 7. Sign again
.\sign.bat
```

### Automated Build (CI/CD)

The GitHub Actions workflows now **automatically handle this process**:

#### [`publish-sanctum.yml`](.github/workflows/publish-sanctum.yml:56-106)
- Detects changes to Sanctum components
- Builds only what changed (driver or usermode)
- Automatically extracts hash and updates `build.rs`
- Rebuilds with correct hash
- Creates PR with signed binaries

#### [`publish-binaries.yml`](.github/workflows/publish-binaries.yml:257-304)
- Manual workflow dispatch for full binary rebuild
- Same automated hash extraction and update process
- Builds all project components including Sanctum

### Key Code Sections

#### [`build.rs`](build.rs:9-15) - ELAM Resource Embedding
```rust
let elam_rc_content = r#"MicrosoftElamCertificateInfo  MSElamCertInfoID
    {
        1,                        
        L"51DEBDEBFBBF88FECB511184B6A7FEF8EFF005C7C090BB826048CCF988689674\0", // To-Be-Signed Hash
        0x800C,                   
        L"\0"                     
    }"#;
```

This hash **must match** the certificate used to sign the driver.

#### [`cert.ps1`](cert.ps1:13-16) - ELAM Certificate Generation
```powershell
$Cert = New-SelfSignedCertificate -Subject $CertSubject `
    -CertStoreLocation $CertStore `
    -HashAlgorithm SHA256 `
    -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")
```

The `TextExtension` parameter adds the ELAM EKU (Enhanced Key Usage):
- `1.3.6.1.4.1.311.61.4.1` - Early Launch Anti-Malware Driver
- `1.3.6.1.5.5.7.3.3` - Code Signing

#### [`sign.bat`](sign.bat:33-46) - Driver Signing
```batch
:: Remove WDK test signature
signtool remove /s "%DRIVER_PATH%"

:: Sign with ELAM certificate
signtool.exe sign /fd SHA256 /v /ph /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%DRIVER_PATH%"
```

## Automated Workflow Logic

The workflows use PowerShell to automate the hash extraction and update:

```powershell
# Extract hash from signed driver
$certOutput = certmgr.exe -v target\release\sanctum_package\sanctum.sys
$hashLines = $certOutput | Select-String -Pattern "Content Hash \(To-Be-Signed Hash\)::" -Context 0,3

# Parse and clean the hash
$hashText = $hashLines[0].Context.PostContext -join ""
$hash = $hashText -replace '\s+', '' -replace '0x', ''

# Update build.rs with regex replacement
$buildRsContent = Get-Content build.rs -Raw
$buildRsContent = $buildRsContent -replace 'L"[0-9A-F]+\\0"', "L`"$hash\0`""
Set-Content build.rs $buildRsContent

# Rebuild with correct hash
cargo clean
cargo make release
.\sign.bat release
```

## Why This Matters for ELAM

ELAM drivers load **before** Windows boot, before any other drivers. Windows validates:

1. The driver is signed with a valid ELAM certificate
2. The embedded hash in the driver matches the certificate's hash
3. The certificate has the correct EKU extensions

If these don't match, Windows **refuses to load the driver** and the system won't boot properly.

## Distribution Strategy

Since `sanctum.sys` cannot be committed:

1. **CI/CD builds** generate environment-specific binaries
2. **Artifacts are uploaded** to GitHub Actions artifacts
3. **PRs are created** with the built binaries in `hydradragon/Sanctum/`
4. **Users download** pre-built binaries from releases
5. **Developers build locally** following the manual process

## References

- [Microsoft ELAM Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)
- [Windows Driver Samples - ELAM](https://github.com/microsoft/Windows-driver-samples/tree/main/security/elam)
- [Sanctum README](readme.md)
- [FluxSec Blog](https://fluxsec.red/)

## Troubleshooting

### "Driver failed to load" or "Code 52"
- The hash in `build.rs` doesn't match the certificate
- Rebuild following the complete process above

### "Certificate not found"
- Run `cert.ps1` first to generate the certificate
- Check that `sanctum.pfx` exists in the driver directory

### "Failed to compile ELAM resource file"
- Ensure you're running from Developer Command Prompt
- `rc.exe` must be in PATH (part of Windows SDK)

### Hash extraction fails in CI
- Check that `certmgr.exe` is available in the Windows runner
- Verify the regex pattern matches the certmgr output format
