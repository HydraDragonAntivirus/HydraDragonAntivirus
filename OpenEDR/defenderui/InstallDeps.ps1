$ErrorActionPreference = 'Stop'

function Install-Net9 {
    $netDir = "C:\Program Files\dotnet\shared\Microsoft.WindowsDesktop.App"
    if (Test-Path $netDir) {
        # 9.0.17 veya daha üstü kurulu mu kontrol et
        $dirs = Get-ChildItem -Path $netDir | Where-Object { [version]$_.Name -ge [version]'9.0.17' }
        if ($dirs) {
            Write-Host ".NET 9 (>= 9.0.17) Desktop Runtime zaten kurulu."
            return
        }
    }
    
    Write-Host ".NET 9 Desktop Runtime indiriliyor..."
    $url = "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.17/windowsdesktop-runtime-9.0.17-win-x64.exe"
    $outPath = Join-Path $env:TEMP "net9-setup.exe"
    Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing
    
    Write-Host "Kuruluyor..."
    $proc = Start-Process -FilePath $outPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
        Write-Host ".NET 9 başarıyla kuruldu."
    } else {
        Write-Host "HATA: .NET 9 kurulumu başarisiz oldu (Kod: $($proc.ExitCode))."
    }
}

function Install-WinAppSDK {
    # WinUI 3 için gerekli Windows App SDK kontrolü (genel paket)
    $installed = Get-AppxPackage -Name "*Microsoft.WindowsAppRuntime*"
    if ($installed) {
        Write-Host "Windows App SDK zaten kurulu."
        return
    }

    Write-Host "Windows App SDK indiriliyor..."
    # 1.6 veya güncel x64 runtime bootstrapper
    $url = "https://aka.ms/windowsappsdk/1.6/1.6.241114003/windowsappruntimeinstall-x64.exe"
    $outPath = Join-Path $env:TEMP "wasdk-setup.exe"
    Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing
    
    Write-Host "Kuruluyor..."
    $proc = Start-Process -FilePath $outPath -ArgumentList "--quiet" -Wait -PassThru
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
        Write-Host "Windows App SDK başarıyla kuruldu."
    } else {
        Write-Host "Uyarı: Windows App SDK kurulum kodu: $($proc.ExitCode)."
    }
}

try {
    Install-Net9
    Install-WinAppSDK
} catch {
    Write-Host "Gereksinimler yüklenirken bir hata oluştu: $_"
}
