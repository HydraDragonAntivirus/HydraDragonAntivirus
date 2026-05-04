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
    
    # Export PFX if it doesn't exist
    if (-not (Test-Path $PfxPath)) {
        Write-Host "[*] Exporting certificate to PFX..."
        $PasswordSecure = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
        Export-PfxCertificate -Cert $Cert -FilePath $PfxPath -Password $PasswordSecure | Out-Null
        Write-Host "[+] PFX exported: $PfxPath"
    }
}

# 2) Trust the certificate locally
Write-Host "[*] Ensuring certificate is in Trusted Root and Trusted Publisher stores..."
$certData = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$tempCertFile = [System.IO.Path]::GetTempFileName() + ".cer"
[System.IO.File]::WriteAllBytes($tempCertFile, $certData)
certutil -addstore -f Root $tempCertFile | Out-Null
certutil -addstore -f TrustedPublisher $tempCertFile | Out-Null
Remove-Item $tempCertFile

# 3) Locate signtool.exe - use correct architecture
$Arch = "x64"
Write-Host "[*] Using x64 architecture for signtool"

# Find the latest Windows SDK version directory
$KitsPath = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
$SdkVersions = Get-ChildItem -Path $KitsPath -Directory |
               Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
               Sort-Object -Property Name -Descending

$SignTool = $null
foreach ($SdkVersion in $SdkVersions) {
    $SignToolPath = Join-Path $SdkVersion.FullName "$Arch\signtool.exe"
    if (Test-Path $SignToolPath) {
        $SignTool = $SignToolPath
        Write-Host "[*] Found signtool.exe in SDK version: $($SdkVersion.Name)"
        break
    }
}

if (-not $SignTool) {
    throw "signtool.exe not found for architecture $Arch in Windows Kits directory."
}

Write-Host "[*] Using SignTool: $SignTool"

# 4) Sign edrdrv.sys
$DriverPath = Join-Path $OutDir "edrdrv.sys"
if (Test-Path $DriverPath) {
    Write-Host "[*] Signing $DriverPath..."
    & $SignTool sign /v /fd SHA256 /sha1 $($Cert.Thumbprint) /t "http://timestamp.digicert.com" $DriverPath
} else {
    Write-Host "[!] edrdrv.sys not found at $DriverPath. Checking other locations..."
    $AltPaths = Get-ChildItem -Path $EdrRoot -Recurse -Filter "edrdrv.sys" | Select-Object -ExpandProperty FullName
    foreach ($Path in $AltPaths) {
        Write-Host "[*] Signing alternative: $Path"
        & $SignTool sign /v /fd SHA256 /sha1 $($Cert.Thumbprint) /t "http://timestamp.digicert.com" $Path
    }
}

Write-Host "[+] Signing complete."
