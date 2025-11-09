using System.Diagnostics;
using System.ServiceProcess;

namespace HydraDragonAntivirusLauncher
{
    public class Worker(ILogger<Worker> logger) : BackgroundService
    {
        private readonly ILogger<Worker> _logger = logger;
        private Process? _childProcess;  // Marked as nullable
        private Process? _guiProcess;    // Marked as nullable

        // Restart supervision settings
        private readonly bool _restartOnCrash = true;
        private readonly int _initialBackoffMs = 1000;
        private readonly int _maxBackoffMs = 20000;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Worker starting at: {time}", DateTimeOffset.Now);

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
            // HydraDragon supervision loop
            // --------------------------------------------------
            int backoff = _initialBackoffMs;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Try to start the child process (and GUI)
                    StartHydraDragon();

                    if (_childProcess == null)
                    {
                        _logger.LogError("Child process failed to start. Aborting supervision loop.");
                        break;
                    }

                    // Wait until either the child exits or service is cancelled
                    var exitedOrCancelled = await WaitForChildExitOrCancellationAsync(_childProcess, stoppingToken);

                    if (stoppingToken.IsCancellationRequested)
                    {
                        // Service stopping: ensure child and gui are terminated
                        await StopChildAsync();
                        break;
                    }

                    // Child exited by itself
                    _logger.LogWarning("HydraDragon exited with code {code}", _childProcess.ExitCode);

                    // Dispose child and consider restart
                    _childProcess.Dispose();
                    _childProcess = null;

                    // Also ensure GUI is stopped when child exits (so restart will re-open it)
                    await StopGuiIfOwnedAsync();

                    if (_restartOnCrash && !stoppingToken.IsCancellationRequested)
                    {
                        _logger.LogInformation("Restarting HydraDragon in {ms} ms", backoff);
                        await Task.Delay(backoff, stoppingToken);
                        backoff = Math.Min(backoff * 2, _maxBackoffMs);
                        continue;
                    }
                    else
                    {
                        break;
                    }
                }
                catch (OperationCanceledException)
                {
                    // stoppingToken triggered
                    await StopChildAsync();
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled exception in worker supervision loop.");
                    // small delay to avoid tight crash loops
                    await Task.Delay(2000, stoppingToken);
                }
            }

            _logger.LogInformation("Worker stopping at: {time}", DateTimeOffset.Now);
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

            // 2b) OwlyShield Service: Start and monitor for up to 30 seconds
            await MonitorAndStartServiceAsync("OwlyShield Service", TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(1), ct);

            // 3) um_engine.exe
            await RunExeAsync(umPath);

            // 4) app.exe
            await RunExeAsync(appPath);
        }

        // ------------------------------------------------------------
        // Service Monitoring
        // ------------------------------------------------------------
        private async Task MonitorAndStartServiceAsync(string serviceName, TimeSpan timeout, TimeSpan checkInterval, CancellationToken ct)
        {
            _logger.LogInformation("Starting monitoring for service '{service}' for a maximum of {seconds} seconds.", serviceName, timeout.TotalSeconds);
            var stopwatch = Stopwatch.StartNew();

            while (stopwatch.Elapsed < timeout && !ct.IsCancellationRequested)
            {
                bool isRunning = false;
                try
                {
                    using var sc = new ServiceController(serviceName);
                    isRunning = (sc.Status == ServiceControllerStatus.Running);
                }
                catch (InvalidOperationException)
                {
                    // Service is not installed
                    _logger.LogWarning("Service '{service}' is not installed. Stopping monitoring.", serviceName);
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error checking status of service '{service}'.", serviceName);
                }

                if (isRunning)
                {
                    _logger.LogInformation("Service '{service}' is running. Monitoring stopped.", serviceName);
                    return;
                }
                else
                {
                    _logger.LogInformation("Service '{service}' is not running. Attempting to start...", serviceName);
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "sc",
                            Arguments = $"start \"{serviceName}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to issue 'sc start' for service '{service}'.", serviceName);
                    }
                }

                // Wait for the next check interval
                await Task.Delay(checkInterval, ct);
            }

            if (stopwatch.Elapsed >= timeout)
            {
                _logger.LogWarning("Stopped monitoring for service '{service}' after timeout of {seconds} seconds.", serviceName, timeout.TotalSeconds);
            }
        }


        // ------------------------------------------------------------
        // HydraDragon supervision methods
        // ------------------------------------------------------------
        private void StartHydraDragon()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // ------------------------
            // Try to start the GUI (Moved to top per request)
            // ------------------------
            try
            {
                // Path relative to service base folder
                string guiRelative = Path.Combine("HydraDragonAntivirusGUI", "HydraDragonAntivirusGUI.exe");
                string guiFull = Path.Combine(baseDir, guiRelative);

                if (File.Exists(guiFull))
                {
                    // If another instance already running, skip launching another
                    bool alreadyRunning = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(guiFull)).Length > 0;
                    if (!alreadyRunning)
                    {
                        var guiPsi = new ProcessStartInfo
                        {
                            FileName = guiFull,
                            WorkingDirectory = Path.GetDirectoryName(guiFull) ?? baseDir,  // Null-coalescing added
                            UseShellExecute = true, // run with normal shell so GUI appears on desktop
                        };

                        _guiProcess = Process.Start(guiPsi);
                        _logger.LogInformation("Launched GUI at {path} (pid {pid})", guiFull, _guiProcess?.Id);
                    }
                    else
                    {
                        _logger.LogInformation("GUI already running, will not start a second instance: {exe}", guiFull);
                    }
                }
                else
                {
                    _logger.LogDebug("GUI executable not found at: {path}", guiFull);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to start GUI executable.");
            }

            // ------------------------
            // Start HydraDragon Core
            // ------------------------
            string venvPath = Path.Combine(baseDir, "venv");
            string activateBat = Path.Combine(venvPath, "Scripts", "activate.bat");

            if (!File.Exists(activateBat))
            {
                _logger.LogError("activate.bat not found at: {path}", activateBat);
                _childProcess = null;
                return;
            }

            // Use cmd.exe to run activate.bat && poetry run hydradragon
            string fileName = "cmd.exe";
            string arguments = $"/c \"\"{activateBat}\" && poetry run hydradragon\"";

            _logger.LogInformation("Launching hydradragon using activate.bat: {bat}", activateBat);

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = baseDir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8
            };

            _childProcess = new Process { StartInfo = psi, EnableRaisingEvents = true };

            _childProcess.OutputDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data)) _logger.LogInformation("[HydraDragon] {msg}", e.Data);
            };

            _childProcess.ErrorDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data)) _logger.LogError("[HydraDragon ERR] {msg}", e.Data);
            };

            _childProcess.Exited += (s, e) =>
            {
                _logger.LogDebug("Child process Exited event fired (pid {pid}).", _childProcess?.Id);
            };

            try
            {
                if (!_childProcess.Start())
                {
                    _logger.LogError("Failed to start child process (Process.Start returned false).");
                    _childProcess = null;
                    return;
                }

                _childProcess.BeginOutputReadLine();
                _childProcess.BeginErrorReadLine();

                _logger.LogInformation("Started HydraDragon child process (pid {pid}) with {file} {args}", _childProcess.Id, fileName, arguments);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start HydraDragon child process.");
                _childProcess = null;
                return;
            }
        }

        private async Task<bool> WaitForChildExitOrCancellationAsync(Process? child, CancellationToken cancellationToken)
        {
            if (child == null) return true;

            var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            void Handler(object? s, EventArgs e) => tcs.TrySetResult(null);
            child.Exited += Handler;

            try
            {
                // If already exited, return immediately
                if (child.HasExited) return true;

                var cancellationTask = Task.Delay(Timeout.Infinite, cancellationToken);
                var completed = await Task.WhenAny(tcs.Task, cancellationTask).ConfigureAwait(false);

                return completed == tcs.Task;
            }
            finally
            {
                child.Exited -= Handler;
            }
        }

        private async Task StopChildAsync()
        {
            if (_childProcess == null) return;

            try
            {
                if (!_childProcess.HasExited)
                {
                    _logger.LogInformation("Killing child process tree (pid {pid}).", _childProcess.Id);
                    _childProcess.Kill(true); // kill entire process tree

                    // Wait a short time for it to exit
                    if (!_childProcess.WaitForExit(5000))
                    {
                        _logger.LogWarning("Child did not exit within timeout after Kill().");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error while stopping HydraDragon child process.");
            }
            finally
            {
                try { _childProcess?.Dispose(); } catch { }
                _childProcess = null;
            }

            // Ensure GUI is stopped as well if we started it
            await StopGuiIfOwnedAsync();

            // small grace delay
            await Task.Delay(50);
        }

        private async Task StopGuiIfOwnedAsync()
        {
            if (_guiProcess == null) return;

            try
            {
                // if still running try graceful close first (CloseMainWindow) then kill
                if (!_guiProcess.HasExited)
                {
                    _logger.LogInformation("Stopping GUI process (pid {pid}).", _guiProcess.Id);
                    try
                    {
                        _guiProcess.CloseMainWindow();
                    }
                    catch { /* ignore */ }

                    // wait a bit for it to exit
                    if (!_guiProcess.WaitForExit(2000))
                    {
                        try
                        {
                            _guiProcess.Kill(true);
                        }
                        catch (Exception exKill)
                        {
                            _logger.LogWarning(exKill, "Failed to kill GUI process.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error while stopping GUI process.");
            }
            finally
            {
                try { _guiProcess?.Dispose(); } catch { }
                _guiProcess = null;
            }

            await Task.CompletedTask;
        }
    }
}