using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using HydraDragonClient.Config;
using HydraDragonClient.Network;
using HydraDragonClient.Protocol;
using HydraDragonClient.ScreenCapture;
using HydraDragonClient.Security;
using HydraDragonClient.Input;

namespace HydraDragonClient.Remote
{
    /// <summary>
    /// Remote server that accepts connections and shares screen/input
    /// </summary>
    public class RemoteServer : IDisposable
    {
        private TcpListener? _listener;
        private TcpMessageChannel? _activeClient;
        private ScreenCapturer? _capturer;
        private CancellationTokenSource? _cts;
        private Task? _listenTask;
        private Task? _screenTask;
        private bool _disposed;

        private string _sessionPassword = "";
        private readonly AppSettings _settings;
        private readonly List<ConnectionLog> _connectionLogs = new();

        public bool IsRunning => _listener != null && !_disposed;
        public bool HasActiveConnection => _activeClient?.IsConnected ?? false;
        public string SessionPassword => _sessionPassword;
        public IReadOnlyList<ConnectionLog> ConnectionLogs => _connectionLogs;

        // Events
        public event EventHandler<ConnectionRequestEventArgs>? ConnectionRequested;
        public event EventHandler<string>? ClientConnected;
        public event EventHandler? ClientDisconnected;
        public event EventHandler<string>? StatusChanged;
        public event EventHandler<string>? Error;

        public RemoteServer(AppSettings settings)
        {
            _settings = settings;
        }

        /// <summary>
        /// Start the remote server
        /// </summary>
        public void Start()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(RemoteServer));
            if (IsRunning) return;

            _sessionPassword = CryptoProvider.GenerateSessionPassword();
            _cts = new CancellationTokenSource();

            _listener = new TcpListener(IPAddress.Any, _settings.Port);
            _listener.Start();

            _listenTask = ListenForConnectionsAsync(_cts.Token);

            StatusChanged?.Invoke(this, $"Server started on port {_settings.Port}. Password: {_sessionPassword}");
        }

        /// <summary>
        /// Stop the remote server
        /// </summary>
        public void Stop()
        {
            if (!IsRunning) return;

            _cts?.Cancel();
            DisconnectClient("Server stopped");
            
            try { _listener?.Stop(); } catch { }
            _listener = null;

            StatusChanged?.Invoke(this, "Server stopped");
        }

        /// <summary>
        /// Generate a new session password
        /// </summary>
        public void RegeneratePassword()
        {
            _sessionPassword = CryptoProvider.GenerateSessionPassword();
            StatusChanged?.Invoke(this, $"New password: {_sessionPassword}");
        }

        /// <summary>
        /// Accept or reject pending connection
        /// </summary>
        public void RespondToConnection(bool accept)
        {
            _pendingAccept = accept;
            _pendingEvent?.Set();
        }

        private bool _pendingAccept;
        private ManualResetEventSlim? _pendingEvent;

        private async Task ListenForConnectionsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener!.AcceptTcpClientAsync(ct);
                    _ = HandleConnectionAsync(client, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Error?.Invoke(this, ex.Message);
                }
            }
        }

        private async Task HandleConnectionAsync(TcpClient tcpClient, CancellationToken ct)
        {
            var channel = new TcpMessageChannel(tcpClient);
            var remoteEp = channel.RemoteEndPoint;

            try
            {
                // Validate LAN connection
                var ipPart = remoteEp.Split(':')[0];
                if (!CryptoProvider.IsLanAddress(ipPart))
                {
                    await SendResponse(channel, false, "Only LAN connections allowed", ct);
                    channel.Dispose();
                    return;
                }

                // Wait for connect request
                var data = await channel.ReceiveAsync(ct);
                if (data == null)
                {
                    channel.Dispose();
                    return;
                }

                var msg = ProtocolMessage.Deserialize(data);
                if (msg is not ConnectRequest request)
                {
                    channel.Dispose();
                    return;
                }

                // Verify password
                if (!CryptoProvider.VerifyPassword(_sessionPassword, request.PasswordHash))
                {
                    await SendResponse(channel, false, "Invalid password", ct);
                    channel.Dispose();
                    return;
                }

                // Check for existing connection
                if (_activeClient?.IsConnected ?? false)
                {
                    await SendResponse(channel, false, "Another client is already connected", ct);
                    channel.Dispose();
                    return;
                }

                // Request user consent
                _pendingEvent = new ManualResetEventSlim(false);
                ConnectionRequested?.Invoke(this, new ConnectionRequestEventArgs
                {
                    RemoteAddress = ipPart,
                    ClientName = request.ClientName
                });

                // Wait for user response (max 30 seconds)
                var responded = _pendingEvent.Wait(TimeSpan.FromSeconds(30), ct);
                
                if (!responded || !_pendingAccept)
                {
                    await SendResponse(channel, false, "Connection denied by user", ct);
                    channel.Dispose();
                    return;
                }

                // Accept connection
                _activeClient = channel;
                _capturer = new ScreenCapturer(_settings.JpegQuality);

                await SendResponse(channel, true, "Connected", ct, _capturer.Width, _capturer.Height);

                _connectionLogs.Add(new ConnectionLog
                {
                    RemoteAddress = ipPart,
                    ClientName = request.ClientName,
                    ConnectedAt = DateTime.Now
                });

                ClientConnected?.Invoke(this, ipPart);

                // Start screen streaming and input handling
                _screenTask = StreamScreenAsync(ct);
                await HandleInputAsync(ct);
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, ex.Message);
            }
            finally
            {
                DisconnectClient("Connection ended");
            }
        }

        private async Task SendResponse(TcpMessageChannel channel, bool accepted, string reason, 
            CancellationToken ct, int width = 0, int height = 0)
        {
            var response = new ConnectResponse
            {
                Accepted = accepted,
                Reason = reason,
                ScreenWidth = width,
                ScreenHeight = height
            };
            await channel.SendAsync(response.Serialize(), ct);
        }

        private async Task StreamScreenAsync(CancellationToken ct)
        {
            var frameInterval = 1000 / _settings.ScreenFps;

            while (!ct.IsCancellationRequested && (_activeClient?.IsConnected ?? false))
            {
                try
                {
                    var startTime = Environment.TickCount;

                    var jpeg = _capturer!.CaptureScreen();
                    var frame = new ScreenFrame
                    {
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ImageBase64 = Convert.ToBase64String(jpeg)
                    };

                    await _activeClient!.SendAsync(frame.Serialize(), ct);

                    var elapsed = Environment.TickCount - startTime;
                    var delay = Math.Max(1, frameInterval - elapsed);
                    await Task.Delay(delay, ct);
                }
                catch (OperationCanceledException) { break; }
                catch { break; }
            }
        }

        private readonly Dictionary<string, FileStream> _activeTransfers = new();

        private async Task HandleInputAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && (_activeClient?.IsConnected ?? false))
            {
                try
                {
                    var data = await _activeClient!.ReceiveAsync(ct);
                    if (data == null) break;

                    var msg = ProtocolMessage.Deserialize(data);
                    
                    switch (msg)
                    {
                        case KeyboardInput ki:
                            InputInjector.InjectKeyboard(ki);
                            break;
                            
                        case MouseInput mi when _settings.EnableMouse:
                            InputInjector.InjectMouse(mi, _capturer!.Width, _capturer.Height);
                            break;

                        case FileTransferRequest ftr:
                            // Save to Desktop by default
                            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                            var savePath = Path.Combine(desktopPath, ftr.FileName);
                            try
                            {
                                var fs = new FileStream(savePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);
                                _activeTransfers[ftr.TransferId] = fs;
                                StatusChanged?.Invoke(this, $"Receiving file: {ftr.FileName} ({ftr.FileSize / 1024} KB)");
                            }
                            catch (Exception ex)
                            {
                                Error?.Invoke(this, $"Failed to start file transfer: {ex.Message}");
                            }
                            break;

                        case FileChunk fc:
                            if (_activeTransfers.TryGetValue(fc.TransferId, out var fileStream))
                            {
                                var bytes = Convert.FromBase64String(fc.DataBase64);
                                await fileStream.WriteAsync(bytes, 0, bytes.Length, ct);
                                
                                if (fc.IsLast)
                                {
                                    fileStream.Close();
                                    await fileStream.DisposeAsync();
                                    _activeTransfers.Remove(fc.TransferId);
                                    StatusChanged?.Invoke(this, "File transfer complete");
                                }
                            }
                            break;
                            
                        case DisconnectMessage:
                            return;
                            
                        case Heartbeat:
                            // Respond to heartbeat
                            await _activeClient.SendAsync(new Heartbeat 
                            { 
                                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() 
                            }.Serialize(), ct);
                            break;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { break; }
            }
        }

        private void DisconnectClient(string reason)
        {
            if (_activeClient != null)
            {
                // Update connection log
                var log = _connectionLogs.FindLast(l => l.DisconnectedAt == null);
                if (log != null)
                {
                    log.DisconnectedAt = DateTime.Now;
                    log.DisconnectReason = reason;
                }

                try { _activeClient.Dispose(); } catch { }
                _activeClient = null;
                
                ClientDisconnected?.Invoke(this, EventArgs.Empty);
            }

            try { _capturer?.Dispose(); } catch { }
            _capturer = null;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            Stop();
            _cts?.Dispose();
            _pendingEvent?.Dispose();
        }
    }

    public class ConnectionRequestEventArgs : EventArgs
    {
        public string RemoteAddress { get; set; } = "";
        public string ClientName { get; set; } = "";
    }

    public class ConnectionLog
    {
        public string RemoteAddress { get; set; } = "";
        public string ClientName { get; set; } = "";
        public DateTime ConnectedAt { get; set; }
        public DateTime? DisconnectedAt { get; set; }
        public string? DisconnectReason { get; set; }
        
        public TimeSpan Duration => (DisconnectedAt ?? DateTime.Now) - ConnectedAt;
    }
}
