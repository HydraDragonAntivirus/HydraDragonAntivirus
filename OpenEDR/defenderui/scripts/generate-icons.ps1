# DefenderUI Icon Generator
# s32.jpg kaynak dosyasından tüm gereken app icon boyutlarını üretir

Add-Type -AssemblyName System.Drawing

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$sourcePath = Join-Path $repoRoot 'iconlogo\s32.jpg'
$assetsDir = Join-Path $repoRoot 'Assets'

if (-not (Test-Path $sourcePath)) {
    Write-Error "Kaynak dosya bulunamadi: $sourcePath"
    exit 1
}

Write-Host "Kaynak: $sourcePath" -ForegroundColor Cyan
$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
Write-Host "Boyut: $($sourceImage.Width) x $($sourceImage.Height)" -ForegroundColor Cyan

function Save-PngAt {
    param(
        [int]$Size,
        [string]$OutputPath
    )
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.DrawImage($sourceImage, 0, 0, $Size, $Size)
    $bmp.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bmp.Dispose()
    Write-Host "  [OK] $OutputPath ($Size x $Size)" -ForegroundColor Green
}

function Save-PngExact {
    param(
        [int]$Width,
        [int]$Height,
        [string]$OutputPath
    )
    $bmp = New-Object System.Drawing.Bitmap($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)

    # Merkeze yerleştir, aspect ratio koru
    $scale = [Math]::Min($Width / $sourceImage.Width, $Height / $sourceImage.Height)
    $newW = [int]($sourceImage.Width * $scale)
    $newH = [int]($sourceImage.Height * $scale)
    $x = ($Width - $newW) / 2
    $y = ($Height - $newH) / 2
    $graphics.DrawImage($sourceImage, $x, $y, $newW, $newH)
    $bmp.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bmp.Dispose()
    Write-Host "  [OK] $OutputPath ($Width x $Height)" -ForegroundColor Green
}

Write-Host "`n=== MSIX Assets Uretiliyor ===" -ForegroundColor Yellow

# Square44x44 (scale-200 => 88x88)
Save-PngAt -Size 88 -OutputPath (Join-Path $assetsDir 'Square44x44Logo.scale-200.png')
Save-PngAt -Size 24 -OutputPath (Join-Path $assetsDir 'Square44x44Logo.targetsize-24_altform-unplated.png')
Save-PngAt -Size 44 -OutputPath (Join-Path $assetsDir 'Square44x44Logo.png')

# Square150x150 (scale-200 => 300x300)
Save-PngAt -Size 300 -OutputPath (Join-Path $assetsDir 'Square150x150Logo.scale-200.png')
Save-PngAt -Size 150 -OutputPath (Join-Path $assetsDir 'Square150x150Logo.png')

# Wide310x150 (scale-200 => 620x300) - aspect ratio different
Save-PngExact -Width 620 -Height 300 -OutputPath (Join-Path $assetsDir 'Wide310x150Logo.scale-200.png')
Save-PngExact -Width 310 -Height 150 -OutputPath (Join-Path $assetsDir 'Wide310x150Logo.png')

# LockScreen (scale-200 => 48x48)
Save-PngAt -Size 48 -OutputPath (Join-Path $assetsDir 'LockScreenLogo.scale-200.png')

# SplashScreen (scale-200 => 1240x600)
Save-PngExact -Width 1240 -Height 600 -OutputPath (Join-Path $assetsDir 'SplashScreen.scale-200.png')
Save-PngExact -Width 620 -Height 300 -OutputPath (Join-Path $assetsDir 'SplashScreen.png')

# StoreLogo (50x50)
Save-PngAt -Size 50 -OutputPath (Join-Path $assetsDir 'StoreLogo.png')

# App logo PNG'leri (UI içinde kullanmak için)
Write-Host "`n=== UI Asset PNG'leri ===" -ForegroundColor Yellow
Save-PngAt -Size 32 -OutputPath (Join-Path $assetsDir 'AppLogo-32.png')
Save-PngAt -Size 64 -OutputPath (Join-Path $assetsDir 'AppLogo-64.png')
Save-PngAt -Size 128 -OutputPath (Join-Path $assetsDir 'AppLogo-128.png')
Save-PngAt -Size 256 -OutputPath (Join-Path $assetsDir 'AppLogo-256.png')

Write-Host "`n=== ICO Dosyasi Uretiliyor ===" -ForegroundColor Yellow
# AppIcon.ico (multi-resolution)
$icoSizes = @(16, 24, 32, 48, 64, 128, 256)
$icoPngs = @{}
foreach ($s in $icoSizes) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.DrawImage($sourceImage, 0, 0, $s, $s)
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $icoPngs[$s] = $ms.ToArray()
    $g.Dispose()
    $bmp.Dispose()
    $ms.Dispose()
}

# ICO dosyasını manuel olarak oluştur (multi-size PNG-embedded ICO)
$icoPath = Join-Path $assetsDir 'AppIcon.ico'
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)

# ICONDIR
$bw.Write([UInt16]0)         # Reserved
$bw.Write([UInt16]1)         # Type: 1=ICO
$bw.Write([UInt16]$icoSizes.Count)  # Image count

# Entries için offset hesapla
$offset = 6 + (16 * $icoSizes.Count)

# ICONDIRENTRY (her boyut icin)
foreach ($s in $icoSizes) {
    $pngData = $icoPngs[$s]
    $w = if ($s -ge 256) { [byte]0 } else { [byte]$s }
    $h = if ($s -ge 256) { [byte]0 } else { [byte]$s }
    $bw.Write([byte]$w)              # Width
    $bw.Write([byte]$h)              # Height
    $bw.Write([byte]0)               # Color count
    $bw.Write([byte]0)               # Reserved
    $bw.Write([UInt16]1)             # Color planes
    $bw.Write([UInt16]32)            # Bits per pixel
    $bw.Write([UInt32]$pngData.Length)  # Size
    $bw.Write([UInt32]$offset)       # Offset
    $offset += $pngData.Length
}

# Image data
foreach ($s in $icoSizes) {
    $bw.Write($icoPngs[$s])
}

$bw.Close()
$fs.Close()
Write-Host "  [OK] $icoPath (multi-res ICO)" -ForegroundColor Green

$sourceImage.Dispose()

Write-Host "`n=== TUM ICONLAR BASARIYLA URETILDI ===" -ForegroundColor Green