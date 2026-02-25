using System;
using System.Drawing;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using HydraDragonClient.Config;
using HydraDragonClient.Network;
using HydraDragonClient.Protocol;
using HydraDragonClient.Security;

namespace HydraDragonClient.Client
{
    /// <summary>
    /// Client that connects to remote servers
    /// </summary>
    public class RemoteClient : IDisposable
    {
        private TcpClient? _tcpClient;
        private TcpMessageChannel? _channel;
        private CancellationTokenSource? _cts;
        private Task? _receiveTask;
        private bool _disposed;

        private int _remoteWidth;
        private int _remoteHeight;

        public bool IsConnected => _channel?.IsConnected ?? false;
        public int RemoteWidth => _remoteWidth;
        public int RemoteHeight => _remoteHeight;

        // Events
        public event EventHandler<Bitmap>? FrameReceived;
        public event EventHandler<string>? Connected;
        public event EventHandler<string>? Disconnected;
        public event EventHandler<string>? Error;

        /// <summary>
        /// Connect to a remote server
        /// </summary>
        public async Task<bool> ConnectAsync(string host, int port, string password, string clientName = "HydraDragon Client")
        {
            if (_disposed) throw new ObjectDisposedException(nameof(RemoteClient));
            if (IsConnected) throw new InvalidOperationException("Already connected");

            try
            {
                // Validate LAN address
                if (!CryptoProvider.IsLanAddress(host))
                {
                    Error?.Invoke(this, "Only LAN connections are allowed");
                    return false;
                }

                _tcpClient = new TcpClient();
                _tcpClient.NoDelay = true;

                // Connect with timeout
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await _tcpClient.ConnectAsync(host, port, connectCts.Token);

                _channel = new TcpMessageChannel(_tcpClient);
                _cts = new CancellationTokenSource();

                // Send connection request
                var request = new ConnectRequest
                {
                    PasswordHash = CryptoProvider.HashPassword(password),
                    ClientName = clientName
                };
                await _channel.SendAsync(request.Serialize());

                // Wait for response
                var responseData = await _channel.ReceiveAsync(_cts.Token);
                if (responseData == null)
                {
                    Error?.Invoke(this, "No response from server");
                    Disconnect();
                    return false;
                }

                var response = ProtocolMessage.Deserialize(responseData) as ConnectResponse;
                if (response == null)
                {
                    Error?.Invoke(this, "Invalid response from server");
                    Disconnect();
                    return false;
                }

                if (!response.Accepted)
                {
                    Error?.Invoke(this, response.Reason);
                    Disconnect();
                    return false;
                }

                _remoteWidth = response.ScreenWidth;
                _remoteHeight = response.ScreenHeight;

                // Start receiving frames
                _receiveTask = ReceiveFramesAsync(_cts.Token);

                Connected?.Invoke(this, host);
                return true;
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, ex.Message);
                Disconnect();
                return false;
            }
        }

        /// <summary>
        /// Disconnect from the server
        /// </summary>
        public void Disconnect()
        {
            if (!IsConnected && _channel == null) return;

            try
            {
                if (_channel?.IsConnected ?? false)
                {
                    var disconnect = new DisconnectMessage { Reason = "User disconnected" };
                    _channel.SendAsync(disconnect.Serialize()).Wait(1000);
                }
            }
            catch { }

            _cts?.Cancel();

            try { _channel?.Dispose(); } catch { }
            try { _tcpClient?.Dispose(); } catch { }

            _channel = null;
            _tcpClient = null;

            Disconnected?.Invoke(this, "Disconnected");
        }

        /// <summary>
        /// Send a keyboard event
        /// </summary>
        public async Task SendKeyboardAsync(int virtualKeyCode, bool isKeyDown, 
            bool shift = false, bool control = false, bool alt = false)
        {
            if (!IsConnected) return;

            var input = new KeyboardInput
            {
                VirtualKeyCode = virtualKeyCode,
                IsKeyDown = isKeyDown,
                Shift = shift,
                Control = control,
                Alt = alt
            };

            try
            {
                await _channel!.SendAsync(input.Serialize());
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, ex.Message);
            }
        }

        /// <summary>
        /// Send a mouse event
        /// </summary>
        public async Task SendMouseAsync(int x, int y, MouseAction action, int wheelDelta = 0)
        {
            if (!IsConnected) return;

            var input = new MouseInput
            {
                X = x,
                Y = y,
                Action = action,
                WheelDelta = wheelDelta
            };

            try
            {
                await _channel!.SendAsync(input.Serialize());
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, ex.Message);
            }
        }

        /// <summary>
        /// Send a file to the remote server
        /// </summary>
        public async Task SendFileAsync(string filePath)
        {
            if (!IsConnected) return;

            try
            {
                var fileInfo = new FileInfo(filePath);
                var transferId = Guid.NewGuid().ToString();
                
                // 1. Send Request
                var request = new FileTransferRequest
                {
                    TransferId = transferId,
                    FileName = fileInfo.Name,
                    FileSize = fileInfo.Length
                };
                await _channel!.SendAsync(request.Serialize());

                // 2. Send Chunks
                using var fs = File.OpenRead(filePath);
                var buffer = new byte[40960]; // 40KB chunks
                int bytesRead;
                int chunkIndex = 0;

                while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    var chunkData = new byte[bytesRead];
                    Array.Copy(buffer, chunkData, bytesRead);
                    
                    var chunk = new FileChunk
                    {
                        TransferId = transferId,
                        Index = chunkIndex++,
                        DataBase64 = Convert.ToBase64String(chunkData),
                        IsLast = (fs.Position == fs.Length)
                    };

                    await _channel!.SendAsync(chunk.Serialize());
                    
                    // Small delay to prevent network congestion
                    if (chunkIndex % 10 == 0) await Task.Delay(1);
                }
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, $"File transfer error: {ex.Message}");
            }
        }

        private async Task ReceiveFramesAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && IsConnected)
            {
                try
                {
                    var data = await _channel!.ReceiveAsync(ct);
                    if (data == null) break;

                    var msg = ProtocolMessage.Deserialize(data);
                    
                    if (msg is ScreenFrame frame)
                    {
                        var imageBytes = Convert.FromBase64String(frame.ImageBase64);
                        using var ms = new MemoryStream(imageBytes);
                        var bitmap = new Bitmap(ms);
                        FrameReceived?.Invoke(this, bitmap);
                    }
                    else if (msg is DisconnectMessage disconnect)
                    {
                        Error?.Invoke(this, $"Server disconnected: {disconnect.Reason}");
                        break;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Error?.Invoke(this, ex.Message);
                    break;
                }
            }

            Disconnect();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            Disconnect();
            _cts?.Dispose();
        }
    }
}
