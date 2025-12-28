# sign_driver.ps1
param (
    [string]$DriverPath = "hydradragonfirewalldrv.sys"
)

$ErrorActionPreference = "Stop"

Write-Host "--- HydraDragon Driver Signing Utility ---" -ForegroundColor Cyan

# 1. Create Self-Signed Certificate
$CertName = "HydraDragonTestCert"
$CertStorePath = "Cert:\LocalMachine\My"

Write-Host "Checking for existing certificate..."
$OldCert = Get-ChildItem $CertStorePath | Where-Object { $_.Subject -like "*CN=$CertName*" }
if ($OldCert) {
    Write-Host "Removing old certificate..."
    $OldCert | Remove-Item
}

Write-Host "Creating new self-signed certificate..."
$Cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -HashAlgorithm SHA256 -CertStoreLocation $CertStorePath

# 2. Sign the Driver
Write-Host "Signing driver: $DriverPath"
# We use ErrorAction SilentlyContinue because the user doesn't want to trust the cert, 
# which causes a status of UnknownError, but the signature is still applied.
$sig = Set-AuthenticodeSignature -FilePath $DriverPath -Certificate $Cert -HashAlgorithm SHA256
Write-Host "Signature Status: $($sig.Status)"

# 3. Done
Write-Host "Driver signing complete!" -ForegroundColor Green
