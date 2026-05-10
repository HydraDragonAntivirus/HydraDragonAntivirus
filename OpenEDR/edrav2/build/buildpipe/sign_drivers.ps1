$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EdrRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$OutDir = Join-Path $EdrRoot "out"

# 1) Locate or Create Certificate
$PfxPath = Join-Path $ScriptDir "hydradragon.pfx"
$CertPassword = "password"

if (-not (Test-Path $PfxPath)) {
    Write-Host "[i] PFX not found. Creating self-signed certificate..."
    $Cert = New-SelfSignedCertificate -Subject "CN=HydraDragonAntivirus Cert" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")
    
    $PasswordSecure = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $Cert -FilePath $PfxPath -Password $PasswordSecure | Out-Null
    Write-Host "[+] Certificate created and exported: $PfxPath"
} else {
    Write-Host "[+] Using existing PFX: $PfxPath"
}

# 2) Locate Tools
$Arch = "x64"
$KitsPath = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
$SdkVersions = Get-ChildItem -Path $KitsPath -Directory |
               Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
               Sort-Object -Property Name -Descending

$SignTool = $null
$Inf2Cat = $null

foreach ($SdkVersion in $SdkVersions) {
    if (-not $SignTool) {
        $Path = Join-Path $SdkVersion.FullName "$Arch\signtool.exe"
        if (Test-Path $Path) { $SignTool = $Path }
    }
    if (-not $Inf2Cat) {
        $Path = Join-Path $SdkVersion.FullName "x86\inf2cat.exe"
        if (Test-Path $Path) { $Inf2Cat = $Path }
    }
    if ($SignTool -and $Inf2Cat) { break }
}

if (-not $SignTool) { throw "signtool.exe not found." }
Write-Host "[*] Using SignTool: $SignTool"
if ($Inf2Cat) { Write-Host "[*] Using Inf2Cat: $Inf2Cat" }

# 3) Process All Files in Out Directory
if (-not (Test-Path $OutDir)) {
    Write-Host "[!] Out directory not found at $OutDir"
    exit 0
}

Write-Host "`n[*] Processing all driver files in $OutDir..."

# A) Generate Catalog Files if needed
$Infs = Get-ChildItem -Path $OutDir -Filter "*.inf" -Recurse
foreach ($Inf in $Infs) {
    $InfContent = Get-Content $Inf.FullName
    if ($InfContent -match "CatalogFile\s*=\s*(.+)") {
        $CatFileName = $Matches[1].Trim()
        $CatPath = Join-Path (Split-Path $Inf.FullName) $CatFileName
        
        if (-not (Test-Path $CatPath)) {
            if ($Inf2Cat) {
                Write-Host "[*] Generating catalog for $($Inf.Name)..."
                & $Inf2Cat /driver:"$($Inf.DirectoryName)" /os:10_X64,Server10_X64 /verbose
            } else {
                Write-Host "[!] Missing $CatFileName but inf2cat.exe not found."
            }
        }
    }
}

# B) Sign all .sys and .cat files using PFX
$FilesToSign = Get-ChildItem -Path $OutDir -Include "*.sys", "*.cat" -Recurse
foreach ($File in $FilesToSign) {
    Write-Host "[*] Signing $($File.FullName)..."
    & $SignTool sign /v /ph /fd SHA256 /f $PfxPath /p $CertPassword /tr "http://timestamp.digicert.com" /td SHA256 $File.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to sign $($File.Name)"
    }
}

Write-Host "`n[+] Signing process finished."
