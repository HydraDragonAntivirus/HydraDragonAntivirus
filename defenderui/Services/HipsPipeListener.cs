using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DefenderUI.Views;
using Microsoft.UI.Dispatching;

namespace DefenderUI.Services;

/// <summary>
/// HydraDragonAntivirus HIPS soru-cevap named pipe dinleyicisi.
///
/// owlyshield SDK'sı (edrsvc içinde çalışır) bilinmeyen bir program başlatmaya
/// çalıştığında `\\.\pipe\HydraHipEvent` üzerine şu satırı yazar:
///
///     HIPS_ASK:&lt;request_id&gt;|&lt;pid&gt;|&lt;app_name&gt;|&lt;exe_path&gt;|&lt;alert_kind&gt;|&lt;target&gt;|&lt;reason&gt;\n
///
/// Bu servis o pipe'ı server olarak dinler, satırı çözümleyip HipsAlertWindow'u
/// açılır. Kullanıcı bir aksiyon seçince karar, edrsvc'nin HydraNetEvent
/// telemetry pipe'ına aşağıdaki formatta geri yazılır (edrsvc bunu FFI üzerinden
/// owlyshield'ın behavior engine'ine iletir):
///
///     HIPS_DECISION:&lt;request_id&gt;|&lt;decision&gt;\n
///
/// decision değerleri: deny | block | quarantine | allow_once | allow_always
/// </summary>
public sealed class HipsPipeListener : IDisposable
{
    private const string HipsAskPipeName = "HydraHipEvent";
    private const string EdrTelemetryPipeName = "HydraNetEvent";

    private readonly DispatcherQueue _dispatcher;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public HipsPipeListener(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public void Start()
    {
        if (_loop is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => ListenLoopAsync(_cts.Token));
    }

    private async Task ListenLoopAsync(CancellationToken token)
    {
        Log("[HipsPipeListener] ListenLoop started");
        while (!token.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    HipsAskPipeName,
                    PipeDirection.In,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(token);
                Log("[HipsPipeListener] Client connected");

                string? line;
                using (var reader = new StreamReader(server, Encoding.UTF8, false, 4096, leaveOpen: true))
                {
                    line = await reader.ReadLineAsync(token);
                }

                if (!string.IsNullOrEmpty(line))
                {
                    Log($"[HipsPipeListener] Received: {line}");
                    DispatchAsk(line);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException)
            {
                // İstemci erken kapattı — bir sonraki bağlantıya devam.
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log($"[HipsPipeListener] Loop error: {ex}");
            }
        }
    }

    private static void Log(string message)
    {
        try
        {
            File.AppendAllText(
                Path.Combine(AppContext.BaseDirectory, "hips.log"),
                $"[{DateTime.Now:O}] {message}{Environment.NewLine}");
        }
        catch
        {
        }
    }

    private void DispatchAsk(string line)
    {
        const string prefix = "HIPS_ASK:";
        if (!line.StartsWith(prefix, StringComparison.Ordinal))
        {
            return;
        }

        var fields = line.Substring(prefix.Length).Split('|');
        if (fields.Length < 7)
        {
            return;
        }

        var requestId = fields[0];
        var appName = fields[2];
        var exePath = fields[3];

        if (string.IsNullOrEmpty(requestId))
        {
            return;
        }

        _dispatcher.TryEnqueue(() =>
        {
            var window = new HipsAlertWindow(
                string.IsNullOrEmpty(appName) ? "Unknown program" : appName,
                exePath ?? string.Empty,
                decision => SendDecisionAsync(requestId, decision));
            window.Activate();
        });
    }

    /// <summary>
    /// Kullanıcı kararını edrsvc'nin HydraNetEvent telemetry pipe'ına yazar.
    /// edrsvc bu satırı FFI üzerinden owlyshield behavior engine'ine iletir.
    /// </summary>
    private static void SendDecisionAsync(string requestId, string decision)
    {
        string? wire;
        switch (decision)
        {
            case "block":
                wire = "block";
                break;
            case "quarantine":
                wire = "quarantine";
                break;
            case "allow":
                wire = "allow_always";
                break;
            case "ask":
                // "Ask" bir karar değil: uygulama askıda (denied) kalır, SDK
                // sonraki denemede tekrar sorar.
                return;
            default:
                return;
        }

        var payload = Encoding.UTF8.GetBytes($"HIPS_DECISION:{requestId}|{wire}\n");

        Task.Run(() =>
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", "HydraNetEvent", PipeDirection.Out);
                pipe.Connect(1000);
                pipe.Write(payload, 0, payload.Length);
            }
            catch
            {
                // edrsvc dinlemiyorsa karar ulaşamaz; sessiz geç.
            }
        });
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _loop = null;
    }
}