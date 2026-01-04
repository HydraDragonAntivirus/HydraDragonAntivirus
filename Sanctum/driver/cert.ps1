$ErrorActionPreference = "Stop"

# certificate parameters
$CertSubject = "CN=Sanctum ELAM Cert"
$CertStore = "Cert:\CurrentUser\My"
$PfxPath = ".\sanctum.pfx"
$CerPath = ".\sanctum.cer"
$CertPassword = "password" # todo change this for prod

Write-Host "[i] Creating a new self-signed ELAM certificate..."

# https://github.com/microsoft/Windows-driver-samples/tree/main/security/elam
$Cert = New-SelfSignedCertificate -Subject $CertSubject `
    -CertStoreLocation $CertStore `
    -HashAlgorithm SHA256 `
    -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")

Write-Host "[+] Certificate created: $($Cert.Thumbprint)"

# password to secure string
$PasswordSecure = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText

# export the cert to a PFX file
Write-Host "[+] Exporting certificate to PFX file: $PfxPath"
Export-PfxCertificate -Cert $Cert -FilePath $PfxPath -Password $PasswordSecure