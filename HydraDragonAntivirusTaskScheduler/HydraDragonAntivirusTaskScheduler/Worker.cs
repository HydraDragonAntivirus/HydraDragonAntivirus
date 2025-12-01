using System.Diagnostics;

namespace HydraDragonAntivirusTaskScheduler
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("TaskScheduler Worker starting at: {time}", DateTimeOffset.Now);

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
