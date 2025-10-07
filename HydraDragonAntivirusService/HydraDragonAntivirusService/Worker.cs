using System.Diagnostics;

namespace HydraDragonAntivirusService
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private Process _childProcess;

        // Restart supervision settings
        private readonly bool _restartOnCrash = true;
        private readonly int _initialBackoffMs = 1000;
        private readonly int _maxBackoffMs = 30000;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Worker starting at: {time}", DateTimeOffset.Now);

            int backoff = _initialBackoffMs;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Try to start the child process
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
                        // Service stopping: ensure child is terminated
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

        private void StartHydraDragon()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // Try get python from poetry-managed venv
            string pythonExe = TryGetPythonFromPoetry(baseDir, out string poetryWarn);

            string fileName;
            string arguments;

            if (!string.IsNullOrEmpty(pythonExe) && File.Exists(pythonExe))
            {
                fileName = pythonExe;
                arguments = "-m hydradragon"; // run module entrypoint; change if your entrypoint differs
                _logger.LogInformation("Launching hydradragon using venv python: {python}", pythonExe);
            }
            else
            {
                // Fallback: try to run poetry directly (less ideal because poetry spawns real process)
                _logger.LogWarning("Could not locate venv python via Poetry: {warn}. Falling back to 'poetry run hydradragon'.", poetryWarn ?? "no details");
                fileName = "poetry";
                arguments = "run hydradragon";
            }

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = baseDir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
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
            }
        }

        private async Task<bool> WaitForChildExitOrCancellationAsync(Process child, CancellationToken cancellationToken)
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
#if NET5_0_OR_GREATER
                    _logger.LogInformation("Killing child process tree (pid {pid}).", _childProcess.Id);
                    _childProcess.Kill(true); // kill tree if runtime supports it
#else
                    _logger.LogInformation("Killing child process (pid {pid}).", _childProcess.Id);
                    _childProcess.Kill();
#endif
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

        /// <summary>
        /// Runs 'poetry env info -p' to get virtualenv path and returns the python.exe path inside Scripts\python.exe.
        /// On failure returns null and a warning string describing the issue.
        /// </summary>
        private string TryGetPythonFromPoetry(string workingDirectory, out string warning)
        {
            warning = null;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "poetry",
                    Arguments = "env info -p",
                    WorkingDirectory = workingDirectory,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    if (p == null)
                    {
                        warning = "Failed to start 'poetry' process (Process.Start returned null).";
                        return null;
                    }

                    string stdOut = p.StandardOutput.ReadToEnd();
                    string stdErr = p.StandardError.ReadToEnd();
                    p.WaitForExit(5000);

                    if (p.ExitCode != 0)
                    {
                        warning = $"'poetry env info -p' exit code {p.ExitCode}. Stderr: {stdErr}";
                        return null;
                    }

                    if (string.IsNullOrWhiteSpace(stdOut))
                    {
                        warning = "'poetry env info -p' returned empty output.";
                        return null;
                    }

                    string venvPath = stdOut.Trim();
                    string pythonExe = Path.Combine(venvPath, "Scripts", "python.exe");
                    if (File.Exists(pythonExe)) return pythonExe;

                    // On non-windows or atypical venv layout, check 'bin/python' as last resort
                    pythonExe = Path.Combine(venvPath, "bin", "python");
                    if (File.Exists(pythonExe)) return pythonExe;

                    warning = $"Virtualenv found at {venvPath} but python executable not found in expected locations.";
                    return null;
                }
            }
            catch (Exception ex)
            {
                warning = $"Exception while running poetry: {ex.Message}";
                return null;
            }
        }
    }
}
