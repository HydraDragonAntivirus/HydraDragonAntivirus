using System.Diagnostics;

namespace HydraDragonAntivirusLauncher
{
    public class Worker(ILogger<Worker> logger) : BackgroundService
    {
        private readonly ILogger<Worker> _logger = logger;
        private Process? _childProcess;  // Python Engine
        private Process? _avProcess;    // C++ Engine

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
                    // Try to start both processes
                    StartHydraDragonAV();
                    StartHydraDragon();

                    if (_childProcess == null && _avProcess == null)
                    {
                        _logger.LogError("All child processes failed to start. Aborting supervision loop.");
                        break;
                    }

                    // Create task list for waiting
                    var waitTasks = new List<Task<bool>>();
                    if (_childProcess != null) waitTasks.Add(WaitForChildExitOrCancellationAsync(_childProcess, stoppingToken));
                    if (_avProcess != null) waitTasks.Add(WaitForChildExitOrCancellationAsync(_avProcess, stoppingToken));

                    // Wait until ANY child exits or service is cancelled
                    var completedTask = await Task.WhenAny(waitTasks);
                    var exitedOrCancelled = await completedTask;

                    if (stoppingToken.IsCancellationRequested)
                    {
                        // Service stopping: ensure children are terminated
                        await StopAllChildrenAsync();
                        break;
                    }

                    // Check which one exited
                    if (_avProcess != null && _avProcess.HasExited)
                    {
                        _logger.LogWarning("HydraDragonAV (C++ Engine) exited with code {code}", _avProcess.ExitCode);
                        _avProcess.Dispose();
                        _avProcess = null;
                    }

                    if (_childProcess != null && _childProcess.HasExited)
                    {
                        _logger.LogWarning("HydraDragon (Python EDR) exited with code {code}", _childProcess.ExitCode);
                        _childProcess.Dispose();
                        _childProcess = null;
                    }

                    if (_restartOnCrash && !stoppingToken.IsCancellationRequested)
                    {
                        _logger.LogInformation("Restarting failed components in {ms} ms", backoff);
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
        private void StartHydraDragonAV()
        {
            if (_avProcess != null && !_avProcess.HasExited) return;

            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string avPath = Path.Combine(programFiles, "HydraDragonAntivirus", "hydradragon", "HydraDragonAV", "HydraDragonAV.exe");

            if (!File.Exists(avPath))
            {
                _logger.LogError("HydraDragonAV.exe not found at: {path}", avPath);
                return;
            }

            _logger.LogInformation("Launching HydraDragonAV (C++ Engine): {path}", avPath);

            var psi = new ProcessStartInfo
            {
                FileName = avPath,
                WorkingDirectory = Path.GetDirectoryName(avPath),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8
            };

            _avProcess = new Process { StartInfo = psi, EnableRaisingEvents = true };

            _avProcess.OutputDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data)) _logger.LogInformation("[HydraDragonAV] {msg}", e.Data);
            };

            _avProcess.ErrorDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data)) _logger.LogError("[HydraDragonAV ERR] {msg}", e.Data);
            };

            try
            {
                if (!_avProcess.Start())
                {
                    _logger.LogError("Failed to start HydraDragonAV (Process.Start returned false).");
                    _avProcess = null;
                    return;
                }

                _avProcess.BeginOutputReadLine();
                _avProcess.BeginErrorReadLine();

                _logger.LogInformation("Started HydraDragonAV (pid {pid})", _avProcess.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start HydraDragonAV.");
                _avProcess = null;
            }
        }

        private void StartHydraDragon()
        {
            string avPath = Path.Combine(programFiles, "HydraDragonAntivirus");

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

        private async Task StopAllChildrenAsync()
        {
            // Stop AV Process
            if (_avProcess != null)
            {
                try
                {
                    if (!_avProcess.HasExited)
                    {
                        _logger.LogInformation("Killing HydraDragonAV (pid {pid}).", _avProcess.Id);
                        _avProcess.Kill(true);
                        await _avProcess.WaitForExitAsync();
                    }
                }
                catch (Exception ex) { _logger.LogWarning(ex, "Error stopping HydraDragonAV"); }
                finally { _avProcess.Dispose(); _avProcess = null; }
            }

            // Stop Python EDR
            if (_childProcess != null)
            {
                try
                {
                    if (!_childProcess.HasExited)
                    {
                        _logger.LogInformation("Killing HydraDragon (pid {pid}).", _childProcess.Id);
                        _childProcess.Kill(true);
                        await _childProcess.WaitForExitAsync();
                    }
                }
                catch (Exception ex) { _logger.LogWarning(ex, "Error stopping HydraDragon"); }
                finally { _childProcess.Dispose(); _childProcess = null; }
            }

            await Task.Delay(50);
        }

    }
}
