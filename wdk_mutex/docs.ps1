# Script for auto-generating docs which the CI will take care of

# REMEMBER: To un-comment:
# [package.metadata.wdk.driver-model]
# driver-type = "WDM"
#
# in the toml..

Remove-Item -Recurse -Force .\target -ErrorAction SilentlyContinue

$env:RUSTFLAGS    = '--cfg driver_model__driver_type="WDM" -C target-feature=+crt-static'
$env:RUSTDOCFLAGS = '--cfg driver_model__driver_type="WDM"'

cargo doc --no-deps --lib
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Remove-Item -Recurse -Force .\docs -ErrorAction SilentlyContinue
'<meta http-equiv="refresh" content="0; url=wdk_mutex">' | Out-File -Encoding ascii -FilePath .\target\doc\index.html -Force

New-Item -ItemType Directory -Path .\docs | Out-Null
Copy-Item -Path .\target\doc\* -Destination .\docs -Recurse -Force

Write-Output "All done, don't forget to comment out wdm / kmdf in the toml!"