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

Write-Host "[*] Building driver (initial pass) to generate binary..." -ForegroundColor Cyan
cargo make $Profile

if (-not (Test-Path $driverPath)) {
    Write-Error "Driver binary not found at $driverPath. Initial build failed."
}

Write-Host "[*] Extracting To-Be-Signed Hash..." -ForegroundColor Cyan
# We use certutil -dump to get the hash if certmgr is not in PATH
$certOutput = & certutil -v -asn $driverPath
$hashMatch = $certOutput | Select-String -Pattern "Content Hash \(To-Be-Signed Hash\)::" -Context 0,8

if (-not $hashMatch) {
    # Fallback to searching for the raw bytes if the label is missing or different
    Write-Host "[!] Could not find hash label, attempting raw certificate extraction..." -ForegroundColor Yellow
    $certOutput = & certutil -v -dump $driverPath
    $hashMatch = $certOutput | Select-String -Pattern "Content Hash" -Context 0,10
}

if ($hashMatch) {
    $hashBytes = New-Object System.Collections.Generic.List[string]
    foreach ($line in $hashMatch[0].Context.PostContext) {
        # Extract hex bytes (ignoring ASCII column)
        $byteArea = ($line -split "  ", 2)[0]
        $byteMatches = [regex]::Matches($byteArea, '[0-9a-f]{2}') | Select-Object -First 32
        foreach ($byteMatch in $byteMatches) {
            if ($hashBytes.Count -lt 32) {
                $hashBytes.Add($byteMatch.Value.ToUpperInvariant())
            }
        }
        if ($hashBytes.Count -ge 32) { break }
    }
    
    if ($hashBytes.Count -ne 32) {
        Write-Error "Expected 32 SHA256 bytes, got $($hashBytes.Count)."
    }
    
    $hash = -join $hashBytes
    Write-Host "[+] Extracted Hash: $hash" -ForegroundColor Green

    Write-Host "[*] Updating $buildRsPath..." -ForegroundColor Cyan
    $content = Get-Content $buildRsPath -Raw
    $pattern = 'L"[^"]*",\s*// To-Be-Signed Hash'
    
    if ($content -match $pattern) {
        $newContent = $content -replace $pattern, "L`"$hash\0`", // To-Be-Signed Hash"
        [System.IO.File]::WriteAllText((Resolve-Path $buildRsPath), $newContent, [System.Text.UTF8Encoding]::new($false))
        Write-Host "[+] build.rs updated successfully." -ForegroundColor Green
        
        Write-Host "[*] Rebuilding driver with updated hash..." -ForegroundColor Cyan
        cargo clean
        cargo make $Profile
        Write-Host "[+++] SUCCESS: Driver is now synchronized with ELAM identity." -ForegroundColor Green
    } else {
        Write-Error "Could not find hash placeholder in build.rs"
    }
} else {
    Write-Error "Could not extract hash from driver certificate. Ensure signtool has run at least once."
}
