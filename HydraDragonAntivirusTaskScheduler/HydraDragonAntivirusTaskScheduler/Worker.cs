using System.Diagnostics;
using System.Security.Principal;

namespace HydraDragonAntivirusTaskScheduler
{
    public class Worker(ILogger<Worker> logger) : BackgroundService
    {
        private readonly ILogger<Worker> _logger = logger;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("TaskScheduler Worker starting at: {time}", DateTimeOffset.Now);

            // Check for admin privileges and relaunch if needed
            if (!IsRunningAsAdministrator())
            {
                _logger.LogWarning("Application is not running with administrator privileges. Attempting to relaunch...");
                RestartAsAdministrator();
                return; // Exit current instance
            }

            _logger.LogInformation("Running with administrator privileges.");

            // Signal service is ready immediately
            await Task.Yield();

            // --------------------------------------------------
            // Desktop sanctum initialization phase
            // --------------------------------------------------
            try
            {
                string desktopSanctum = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    "sanctum"
                );
                Environment.SetEnvironmentVariable("DESKTOP_SANCTUM", desktopSanctum);

                _logger.LogInformation("Sanctum path set to: {path}", desktopSanctum);

                await RunSanctumSequenceAsync(desktopSanctum, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed during sanctum initialization sequence.");
            }

            // Keep service running until cancellation
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }

        // ------------------------------------------------------------
        // Admin privilege check
        // ------------------------------------------------------------
        private bool IsRunningAsAdministrator()
        {
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check administrator privileges.");
                return false;
            }
        }

        // ------------------------------------------------------------
        // Restart with admin privileges
        // ------------------------------------------------------------
        private void RestartAsAdministrator()
        {
            try
            {
                string? executablePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;

                if (string.IsNullOrEmpty(executablePath))
                {
                    _logger.LogError("Could not determine executable path for restart.");
                    return;
                }

                var psi = new ProcessStartInfo
                {
                    FileName = executablePath,
                    UseShellExecute = true,
                    Verb = "runas", // Request elevation
                    Arguments = string.Join(" ", Environment.GetCommandLineArgs().Skip(1))
                };

                _logger.LogInformation("Launching elevated process: {path}", executablePath);
                Process.Start(psi);

                // Exit current non-elevated instance
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restart application with administrator privileges.");
            }
        }

        // ------------------------------------------------------------
        // Sanctum sequence
        // ------------------------------------------------------------
        private async Task RunSanctumSequenceAsync(string sanctumDir, CancellationToken ct)
        {
            string elamPath = Path.Combine(sanctumDir, "elam_installer.exe");
            string umPath = Path.Combine(sanctumDir, "um_engine.exe");
            string appPath = Path.Combine(sanctumDir, "app.exe");

            // HydraDragonAntivirus paths
            string hydraDragonLauncherPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "HydraDragonAntivirus",
                "HydraDragonAntivirusLauncher.exe"
            );

            // helper for launching exe
            async Task RunExeAsync(string exePath, string args = "", bool fireAndForget = false)
            {
                if (!File.Exists(exePath))
                {
                    _logger.LogWarning("Missing file: {file}", exePath);
                    return;
                }

                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = args,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        StandardOutputEncoding = System.Text.Encoding.UTF8,
                        StandardErrorEncoding = System.Text.Encoding.UTF8
                    };
                    var p = Process.Start(psi);
                    if (p != null)
                    {
                        _logger.LogInformation("Started: {exe} (pid {pid})", exePath, p.Id);

                        if (!fireAndForget)
                        {
                            await Task.Delay(2000, ct); // small delay for sequential order
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Failed to start {exe} - Process.Start returned null", exePath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to start {exe}", exePath);
                }
            }

            // 1) elam_installer.exe
            await RunExeAsync(elamPath);

            // 2) sanctum_ppl_runner: attempt service start
            try
            {
                _logger.LogInformation("Starting sanctum_ppl_runner service...");
                var psi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = "start sanctum_ppl_runner",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8,
                    StandardErrorEncoding = System.Text.Encoding.UTF8
                };
                var scProcess = Process.Start(psi);
                if (scProcess != null)
                {
                    await scProcess.WaitForExitAsync(ct);
                    _logger.LogInformation("sc start sanctum_ppl_runner exited with code: {code}", scProcess.ExitCode);
                }
                await Task.Delay(1500, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to start sanctum_ppl_runner via 'sc start'.");
            }

            // 3) HydraDragonAntivirusLauncher.exe (fire and forget - it's a service host)
            _logger.LogInformation("Starting HydraDragonAntivirusLauncher...");
            await RunExeAsync(hydraDragonLauncherPath, fireAndForget: true);

            // 4) um_engine.exe
            await RunExeAsync(umPath);

            // 5) app.exe
            await RunExeAsync(appPath);

            // 6) HydraDragonFirewall (via Task Scheduler for highest privileges)
            await StartFirewallAsync(sanctumDir, ct);

            _logger.LogInformation("Sanctum sequence completed.");
        }

        private async Task StartFirewallAsync(string sanctumDir, CancellationToken ct)
        {
            string firewallExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HydraDragonAntivirus", "HydraDragonFirewall", "HydraDragonFirewall.exe");

            if (!File.Exists(firewallExe))
            {
                _logger.LogWarning("Firewall executable not found at: {path}", firewallExe);
                return;
            }

            if (IsFirewallRunning())
            {
                _logger.LogInformation("Firewall already running.");
                return;
            }

            try
            {
                string taskName = "HydraDragonFirewall";
                
                _logger.LogInformation("Registering and starting firewall task: {exe}", firewallExe);

                // Create task
                var createPsi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/create /tn \"{taskName}\" /tr \"\\\"{firewallExe}\\\"\" /sc ONCE /st 00:00 /rl HIGHEST /f",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                using (var p = Process.Start(createPsi))
                {
                    if (p != null) await p.WaitForExitAsync(ct);
                }

                // Run task
                var runPsi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/run /tn \"{taskName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(runPsi))
                {
                    if (p != null)
                    {
                         _logger.LogInformation("Triggered HydraDragon Firewall task.");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to manage HydraDragon Firewall task.");
            }
        }

        private bool IsFirewallRunning()
        {
            return Process.GetProcessesByName("HydraDragonFirewall").Length > 0;
        }
    }
}
