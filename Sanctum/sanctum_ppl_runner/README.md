# PPL Runner

This is a Windows service which will run at PPL and launches a child process at the same privilege.

## Troubleshooting

Issues starting the service?

1) Check the exact error in: `Application and Services Logs -> Microsoft -> Windows -> CodeIntegrity -> Operational`
2) Delete and reinstall via registry: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`
3) Check for no imports which will be unsigned (ensure statically linked etc where possible) `dumpbin /dependents target\release\sanctum_ppl_runner.exe`