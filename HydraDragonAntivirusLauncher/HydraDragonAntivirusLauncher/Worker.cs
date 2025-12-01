using System.Diagnostics;

namespace HydraDragonAntivirusLauncher
{
    public class Worker(ILogger<Worker> logger) : BackgroundService
    {
        private readonly ILogger<Worker> _logger = logger;
        private Process? _childProcess;  // Marked as nullable

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
        // HydraDragon supervision methods
        // ------------------------------------------------------------
        private void StartHydraDragon()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;

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

            // small grace delay
            await Task.Delay(50);
        }
    }
}
