<#
.SYNOPSIS
    Synchronizes the ELAM To-Be-Signed hash in build.rs with the current driver binary.
    Run this script after changing driver code but BEFORE the final build.

.EXAMPLE
    .\update_hash.ps1 -Profile release
#>
param(
    [ValidateSet("debug", "release")]
    [string]$Profile = "release"
)

$ErrorActionPreference = "Stop"

$driverPath = "target\$Profile\sanctum_package\sanctum.sys"
$buildRsPath = "build.rs"

$pfxFile = "sanctum.pfx"
$pfxPassword = "password"
$cerFile = "sanctum.cer"

if (-not (Test-Path $pfxFile)) {
    Write-Error "Certificate not found at $pfxFile. Run .\cert.ps1 first."
}

Write-Host "[*] Exporting certificate from PFX to CER..." -ForegroundColor Cyan
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxFile, $pfxPassword)
$bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($cerFile, $bytes)

Write-Host "[*] Extracting Signature Hash from Certificate..." -ForegroundColor Cyan
$certOutput = & certutil -dump $cerFile
$hashMatch = $certOutput | Select-String -Pattern "Signature Hash: ([0-9a-fA-F]{64})"

if ($hashMatch) {
    $hash = $hashMatch.Matches[0].Groups[1].Value.ToUpperInvariant()
    Write-Host "[+] Extracted Hash: $hash" -ForegroundColor Green
    
    # Save the hash to sanctum_elam_hash.txt (used by GitHub Actions)
    $hash | Out-File -FilePath "sanctum_elam_hash.txt" -NoNewline -Encoding ascii

    # Clean up temporary CER file
    if (Test-Path $cerFile) {
        Remove-Item $cerFile -Force
    }

    Write-Host "[*] Updating $buildRsPath..." -ForegroundColor Cyan
    $content = Get-Content $buildRsPath -Raw
    $pattern = 'L"[^"]*",\s*// To-Be-Signed Hash'
    
    if ($content -match $pattern) {
        $newContent = $content -replace $pattern, "L`"$hash\0`", // To-Be-Signed Hash"
        [System.IO.File]::WriteAllText((Resolve-Path $buildRsPath), $newContent, [System.Text.UTF8Encoding]::new($false))
        Write-Host "[+] build.rs updated successfully." -ForegroundColor Green
        
        Write-Host "[*] Building driver with updated hash..." -ForegroundColor Cyan
        cargo make $Profile
        
        Write-Host "[*] Signing driver..." -ForegroundColor Cyan
        if (Test-Path "sign.bat") {
            & .\sign.bat $Profile
        } else {
            Write-Error "sign.bat not found in current directory."
        }
        
        Write-Host "[+++] SUCCESS: Driver is now synchronized with ELAM identity." -ForegroundColor Green
    } else {
        Write-Error "Could not find hash placeholder in build.rs"
    }
} else {
    if (Test-Path $cerFile) {
        Remove-Item $cerFile -Force
    }
    Write-Error "Could not extract Signature Hash from certificate."
}

