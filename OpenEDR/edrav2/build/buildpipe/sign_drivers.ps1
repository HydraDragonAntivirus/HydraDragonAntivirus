$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EdrRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$OutDir = Join-Path $EdrRoot "out\bin\win-Release-x64"

# We reuse the HydraDragon cert if it exists.
$CertSubject = "CN=HydraDragonAntivirus Cert"
$CertStore = "Cert:\CurrentUser\My"
$PfxPath = Join-Path $ScriptDir "hydradragon.pfx"
$CertPassword = "password"

$Cert = Get-ChildItem -Path $CertStore | Where-Object { $_.Subject -like "*HydraDragonAntivirus*" } | Select-Object -First 1

if (-not $Cert) {
    Write-Host "[i] Creating a new self-signed certificate: $CertSubject..."
    $Cert = New-SelfSignedCertificate -Subject $CertSubject `
        -CertStoreLocation $CertStore `
        -HashAlgorithm SHA256 `
        -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")
    
    $PasswordSecure = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $Cert -FilePath $PfxPath -Password $PasswordSecure
    Write-Host "[+] Certificate created: $($Cert.Thumbprint)"
} else {
    Write-Host "[+] Found existing certificate: $($Cert.Thumbprint)"
}

# 2) Trust the certificate locally
Write-Host "[*] Ensuring certificate is in Trusted Root and Trusted Publisher stores..."
$certData = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$tempCertFile = [System.IO.Path]::GetTempFileName() + ".cer"
[System.IO.File]::WriteAllBytes($tempCertFile, $certData)
certutil -addstore -f Root $tempCertFile | Out-Null
certutil -addstore -f TrustedPublisher $tempCertFile | Out-Null
Remove-Item $tempCertFile

# 3) Locate signtool.exe
$SignTool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" | 
            Sort-Object -Property LastWriteTime -Descending | 
            Select-Object -First 1 -ExpandProperty FullName

if (-not $SignTool) {
    throw "signtool.exe not found in Windows Kits directory."
}

Write-Host "[*] Using SignTool: $SignTool"

# 4) Sign edrdrv.sys
$DriverPath = Join-Path $OutDir "edrdrv.sys"
if (Test-Path $DriverPath) {
    Write-Host "[*] Signing $DriverPath..."
    & $SignTool sign /v /fd SHA256 /a /s My /n "$($Cert.Subject)" /t "http://timestamp.digicert.com" $DriverPath
} else {
    Write-Host "[!] edrdrv.sys not found at $DriverPath. Checking other locations..."
    $AltPaths = Get-ChildItem -Path $EdrRoot -Recurse -Filter "edrdrv.sys" | Select-Object -ExpandProperty FullName
    foreach ($Path in $AltPaths) {
        Write-Host "[*] Signing alternative: $Path"
        & $SignTool sign /v /fd SHA256 /a /s My /n "$($Cert.Subject)" /t "http://timestamp.digicert.com" $Path
    }
}

Write-Host "[+] Signing complete."
