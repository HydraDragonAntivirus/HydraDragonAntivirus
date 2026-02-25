using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HydraDragonClient.Network
{
    /// <summary>
    /// Async TCP channel with length-prefixed message framing
    /// </summary>
    public class TcpMessageChannel : IDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private bool _disposed;

        public bool IsConnected => _client.Connected && !_disposed;
        public string RemoteEndPoint => _client.Client.RemoteEndPoint?.ToString() ?? "Unknown";

        public TcpMessageChannel(TcpClient client)
        {
            _client = client;
            _stream = client.GetStream();
            _client.NoDelay = true; // Disable Nagle for lower latency
        }

        /// <summary>
        /// Send raw bytes with length prefix
        /// </summary>
        public async Task SendAsync(byte[] data, CancellationToken ct = default)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(TcpMessageChannel));
            
            await _writeLock.WaitAsync(ct);
            try
            {
                // Send length prefix (4 bytes)
                var lengthBytes = BitConverter.GetBytes(data.Length);
                await _stream.WriteAsync(lengthBytes, 0, 4, ct);
                
                // Send data
                await _stream.WriteAsync(data, 0, data.Length, ct);
                await _stream.FlushAsync(ct);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        /// <summary>
        /// Receive raw bytes with length prefix
        /// </summary>
        public async Task<byte[]?> ReceiveAsync(CancellationToken ct = default)
        {
            if (_disposed) return null;
            
            try
            {
                // Read length prefix
                var lengthBytes = new byte[4];
                var bytesRead = await ReadExactAsync(lengthBytes, 4, ct);
                if (bytesRead < 4) return null;
                
                var length = BitConverter.ToInt32(lengthBytes, 0);
                if (length <= 0 || length > 50_000_000) // Max 50MB per message
                    return null;
                
                // Read data
                var data = new byte[length];
                bytesRead = await ReadExactAsync(data, length, ct);
                if (bytesRead < length) return null;
                
                return data;
            }
            catch (Exception) when (_disposed || ct.IsCancellationRequested)
            {
                return null;
            }
        }

        private async Task<int> ReadExactAsync(byte[] buffer, int count, CancellationToken ct)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                var read = await _stream.ReadAsync(buffer, totalRead, count - totalRead, ct);
                if (read == 0) break; // Connection closed
                totalRead += read;
            }
            return totalRead;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            
            try
            {
                _stream?.Dispose();
                _client?.Dispose();
            }
            catch { }
            
            _writeLock.Dispose();
        }
    }
}
