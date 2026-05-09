using System.Diagnostics;
using System.Security.Principal;

namespace HydraDragonService
{
    public class Worker(ILogger<Worker> logger) : BackgroundService
    {
        private readonly ILogger<Worker> _logger = logger;
        private Process? _pythonProcess; // Python Engine
        private Process? _avProcess;     // C++ Engine
        
        private readonly bool _restartOnCrash = true;
        private readonly int _initialBackoffMs = 1000;
        private readonly int _maxBackoffMs = 20000;
        private readonly string _baseDir = @"C:\Program Files\HydraDragonAntivirus";

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("HydraDragon Unified Service starting at: {time}", DateTimeOffset.Now);

            if (!IsRunningAsAdministrator())
            {
                _logger.LogError("Service is not running as Administrator. Security components cannot be managed. Exiting.");
                return;
            }

            await Task.Yield();

            // --------------------------------------------------
            // 1. HydraDragon Initialization Phase
            // --------------------------------------------------
            try
            {
                string sanctumInstallPath = Path.Combine(_baseDir, "hydradragon", "Sanctum");
                await RunSanctumSequenceAsync(sanctumInstallPath, stoppingToken);
                _logger.LogInformation("HydraDragon Service initialized. Entering supervision loop...");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed during HydraDragon/Sanctum initialization sequence.");
            }

            // --------------------------------------------------
            // 2. Continuous Supervision Loop
            // --------------------------------------------------
            int backoff = _initialBackoffMs;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Monitor Core Engines (AV and Python Engine)
                    StartHydraDragonAV();
                    StartHydraDragonCore();

                    var waitTasks = new List<Task<bool>>();
                    if (_pythonProcess != null) waitTasks.Add(WaitForProcessExitAsync(_pythonProcess, stoppingToken));
                    if (_avProcess != null) waitTasks.Add(WaitForProcessExitAsync(_avProcess, stoppingToken));

                    if (waitTasks.Count > 0)
                    {
                        await Task.WhenAny(waitTasks);
                    }
                    else
                    {
                        await Task.Delay(5000, stoppingToken);
                    }

                    if (stoppingToken.IsCancellationRequested) break;

                    Process? crashedProc = null;
                    if (_avProcess != null && _avProcess.HasExited) crashedProc = _avProcess;
                    else if (_pythonProcess != null && _pythonProcess.HasExited) crashedProc = _pythonProcess;

                    if (crashedProc != null && _restartOnCrash)
                    {
                        string procName = crashedProc == _avProcess ? "C++ Engine" : "Python Engine";
                        
                        _logger.LogWarning("Core engine crashed: {name} (Exit Code: {code}). Restarting...", 
                            procName, crashedProc.ExitCode);
                        
                        await Task.Delay(backoff, stoppingToken);
                        backoff = Math.Min(backoff * 2, _maxBackoffMs);
                    }
                    else
                    {
                        backoff = _initialBackoffMs;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in supervision loop.");
                    await Task.Delay(5000, stoppingToken);
                }
            }

            await StopAllComponentsAsync();
        }

        private async Task RunSanctumSequenceAsync(string sanctumDir, CancellationToken ct)
        {
            _logger.LogInformation("Starting Sanctum sequential startup...");

            string elamPath = Path.Combine(sanctumDir, "elam_installer.exe");
            string umPath = Path.Combine(sanctumDir, "um_engine.exe");
            string appPath = Path.Combine(sanctumDir, "app.exe");

            // 1) ELAM Installer
            await RunExeAsync(elamPath, ct);

            // 2) Start OpenEDR Service
            await StartOpenEDRServiceAsync(ct);

            // 3) Sanctum PPL Runner Service
            await EnsureSanctumPplRunningAsync(ct);

            // 4) UM Engine
            await RunExeAsync(umPath, ct);

            // 5) GUI App
            await RunExeAsync(appPath, ct);

            _logger.LogInformation("Sanctum sequence completed successfully.");
        }

        private async Task RunExeAsync(string exePath, CancellationToken ct, string args = "", bool fireAndForget = false)
        {
            if (!File.Exists(exePath))
            {
                _logger.LogWarning("Missing executable: {file}", exePath);
                return;
            }

            try
            {
                _logger.LogInformation("Starting: {exe}", Path.GetFileName(exePath));
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = args,
                    WorkingDirectory = Path.GetDirectoryName(exePath),
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process? p = Process.Start(psi);
                if (p != null && !fireAndForget)
                {
                    await Task.Delay(2000, ct); // Sequential delay
                }
            }
            catch (Exception ex) { _logger.LogWarning("Failed to launch {exe}: {msg}", exePath, ex.Message); }
        }

        private async Task EnsureSanctumPplRunningAsync(CancellationToken ct)
        {
            try
            {
                _logger.LogInformation("Starting sanctum_ppl_runner service...");
                var psi = new ProcessStartInfo { FileName = "sc", Arguments = "start sanctum_ppl_runner", CreateNoWindow = true, UseShellExecute = false };
                var p = Process.Start(psi);
                if (p != null) await p.WaitForExitAsync(ct);
                await Task.Delay(1500, ct);
            }
            catch (Exception ex) { _logger.LogWarning("Failed to start PPL service: {msg}", ex.Message); }
        }

        private void StartHydraDragonAV()
        {
            if (_avProcess != null && !_avProcess.HasExited) return;
            string avPath = Path.Combine(_baseDir, "hydradragon", "HydraDragonAV", "HydraDragonAV.exe");
            _avProcess = StartProcess(avPath, Path.GetDirectoryName(avPath)!, "[HydraDragonAV]");
        }

        private void StartHydraDragonCore()
        {
            if (_pythonProcess != null && !_pythonProcess.HasExited) return;
            string activateBat = Path.Combine(_baseDir, "venv", "Scripts", "activate.bat");
            _pythonProcess = StartProcess("cmd.exe", _baseDir, "[HydraDragon]", $"/c \"\"{activateBat}\" && poetry run hydradragon\"");
        }

        private Process? StartProcess(string fileName, string workDir, string logPrefix, string args = "")
        {
            if (!File.Exists(fileName) && fileName != "cmd.exe") return null;
            try
            {
                var psi = new ProcessStartInfo { FileName = fileName, Arguments = args, WorkingDirectory = workDir, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
                proc.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) _logger.LogInformation("{prefix} {msg}", logPrefix, e.Data); };
                proc.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) _logger.LogError("{prefix} [STDERR] {msg}", logPrefix, e.Data); };
                if (proc.Start()) { proc.BeginOutputReadLine(); proc.BeginErrorReadLine(); return proc; }
            }
            catch { }
            return null;
        }

        private async Task<bool> WaitForProcessExitAsync(Process proc, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<bool>();
            proc.Exited += (s, e) => tcs.TrySetResult(true);
            if (proc.HasExited) return true;
            using (ct.Register(() => tcs.TrySetCanceled()))
            {
                try { return await tcs.Task; } catch { return false; }
            }
        }

        private async Task StopAllComponentsAsync()
        {
            foreach (var p in new[] { _avProcess, _pythonProcess })
            {
                if (p != null && !p.HasExited) { try { p.Kill(true); await p.WaitForExitAsync(); } catch { } p.Dispose(); }
            }
            Process.Start(new ProcessStartInfo { FileName = "sc", Arguments = "stop sanctum_ppl_runner", CreateNoWindow = true, UseShellExecute = false })?.WaitForExit();
        }

        private async Task StartOpenEDRServiceAsync(CancellationToken ct)
        {
            try
            {
                _logger.LogInformation("Starting OpenEDR service (edrsvc)...");
                var psi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = "start edrsvc",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                var p = Process.Start(psi);
                if (p != null)
                {
                    await p.WaitForExitAsync(ct);
                    string output = await p.StandardOutput.ReadToEndAsync(ct);
                    if (p.ExitCode == 0 || output.Contains("already", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogInformation("OpenEDR service started or already running");
                    }
                    else
                    {
                        _logger.LogWarning("OpenEDR service start returned code {code}: {output}", p.ExitCode, output);
                    }
                }
                await Task.Delay(1500, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to start OpenEDR service (non-fatal): {msg}", ex.Message);
            }
        }

        private bool IsRunningAsAdministrator()
        {
            try { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }
    }
}
