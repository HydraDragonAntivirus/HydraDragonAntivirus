using System.Diagnostics;
using System.Security.Principal;

namespace HydraDragonService
{
    public class Worker(ILogger<Worker> logger) : BackgroundService
    {
        private readonly ILogger<Worker> _logger = logger;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("TaskScheduler Worker starting at: {time}", DateTimeOffset.Now);

            // Check for admin privileges and stop if missing.
            // In a Windows service context, self-elevation (runas/UAC prompt) is not supported.
            if (!IsRunningAsAdministrator())
            {
                _logger.LogError("Application is not running with administrator privileges. This service must be installed/configured to run with required privileges. Exiting.");
                return; // Exit current instance gracefully
            }

            _logger.LogInformation("Running with administrator privileges.");

            // Signal service is ready immediately
            await Task.Yield();

            // --------------------------------------------------
            // HydraDragon Initialization Phase
            // --------------------------------------------------
            try
            {
                _logger.LogInformation("HydraDragon Service initialized. Monitoring tasks...");
                
                // Future: Add HydraDragon-specific startup logic here if needed
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed during HydraDragon initialization sequence.");
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
    }
}
