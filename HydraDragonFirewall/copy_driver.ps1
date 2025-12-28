$DriverPath = Get-ChildItem -Path hydradragonfirewalldrv -Recurse -Filter hydradragonfirewalldrv.sys | Select-Object -ExpandProperty FullName -First 1
if ($DriverPath) {
    Write-Host "Found driver at: $DriverPath"
    Copy-Item -Path $DriverPath -Destination "everything\" -Force
    Write-Host "Copied driver to everything folder."
}
else {
    Write-Error "Could not find hydradragonfirewalldrv.sys source!"
}
