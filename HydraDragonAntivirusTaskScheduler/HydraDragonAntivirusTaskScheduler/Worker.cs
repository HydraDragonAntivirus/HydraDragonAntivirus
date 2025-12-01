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

            // --------------------------------------------------
            // Main worker loop
            // --------------------------------------------------
            while (!stoppingToken.IsCancellationRequested)
            {
                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);
                }
                await Task.Delay(1000, stoppingToken);
            }

            _logger.LogInformation("TaskScheduler Worker stopping at: {time}", DateTimeOffset.Now);
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

            // helper for launching exe
            async Task RunExeAsync(string exePath, string args = "")
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
                    _logger.LogInformation("Started: {exe} (pid {pid})", exePath, p?.Id);
                    await Task.Delay(2000, ct); // small delay for sequential order
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
                Process.Start(psi);
                await Task.Delay(1500, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to start sanctum_ppl_runner via 'sc start'.");
            }

            // 3) um_engine.exe
            await RunExeAsync(umPath);

            // 4) app.exe
            await RunExeAsync(appPath);
        }
    }
}
