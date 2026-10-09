using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// RFC 6455 WebSocket client over any stream (here: the BouncyCastle TLS stream).
    /// .NET 3.5 has no ClientWebSocket. Client frames are masked; pings are answered
    /// inside Receive; fragmented messages are joined.
    /// </summary>
    public sealed class WebSocketClient : IDisposable
    {
        public const int OpText = 1, OpBinary = 2, OpClose = 8, OpPing = 9, OpPong = 10;

        private readonly Stream stream;
        private readonly object writeLock = new object();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();
        private bool closed;

        public WebSocketClient(Stream stream)
        {
            this.stream = stream;
        }

        /// <summary>HTTP/1.1 upgrade. Throws when the server does not switch protocols.</summary>
        public void Handshake(string host, string pathAndQuery)
        {
            var keyBytes = new byte[16];
            rng.GetBytes(keyBytes);
            string key = Convert.ToBase64String(keyBytes);
            string req =
                "GET " + pathAndQuery + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: " + key + "\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "User-Agent: VirusKovReactOS/" + AppInfo.Version + "\r\n" +
                "\r\n";
            byte[] b = Encoding.ASCII.GetBytes(req);
            stream.Write(b, 0, b.Length);
            stream.Flush();

            string status = ReadLine();
            if (status == null || status.IndexOf(" 101", StringComparison.Ordinal) < 0)
                throw new IOException("WebSocket upgrade refused: " + (status ?? "(no answer)"));
            string accept = null;
            string line;
            while (!string.IsNullOrEmpty(line = ReadLine()))
            {
                int colon = line.IndexOf(':');
                if (colon > 0 && line.Substring(0, colon).Trim().Equals("Sec-WebSocket-Accept", StringComparison.OrdinalIgnoreCase))
                    accept = line.Substring(colon + 1).Trim();
            }
            string expected;
            using (var sha1 = new SHA1Managed())
                expected = Convert.ToBase64String(sha1.ComputeHash(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            if (accept != expected)
                throw new IOException("WebSocket upgrade: wrong Sec-WebSocket-Accept");
        }

        private string ReadLine()
        {
            var sb = new StringBuilder();
            while (true)
            {
                int c = stream.ReadByte();
                if (c < 0) return sb.Length == 0 ? null : sb.ToString();
                if (c == '\n') break;
                if (c != '\r') sb.Append((char)c);
                if (sb.Length > 8192) throw new IOException("HTTP header line too long");
            }
            return sb.ToString();
        }

        public void SendText(string text)
        {
            byte[] b = Encoding.UTF8.GetBytes(text);
            SendFrame(OpText, b, 0, b.Length);
        }

        public void SendBinary(byte[] data, int offset, int count)
        {
            SendFrame(OpBinary, data, offset, count);
        }

        private void SendFrame(int opcode, byte[] data, int offset, int count)
        {
            lock (writeLock)
            {
                if (closed) throw new IOException("WebSocket is closed");
                var header = new byte[14];
                int h = 0;
                header[h++] = (byte)(0x80 | opcode); // FIN
                if (count < 126)
                {
                    header[h++] = (byte)(0x80 | count);
                }
                else if (count <= 0xFFFF)
                {
                    header[h++] = 0x80 | 126;
                    header[h++] = (byte)(count >> 8);
                    header[h++] = (byte)count;
                }
                else
                {
                    header[h++] = 0x80 | 127;
                    long len = count;
                    for (int s = 56; s >= 0; s -= 8) header[h++] = (byte)(len >> s);
                }
                var mask = new byte[4];
                rng.GetBytes(mask);
                Buffer.BlockCopy(mask, 0, header, h, 4);
                h += 4;
                var payload = new byte[count];
                for (int i = 0; i < count; i++) payload[i] = (byte)(data[offset + i] ^ mask[i & 3]);
                // One write: some TLS stacks send each Write as its own record.
                var frame = new byte[h + count];
                Buffer.BlockCopy(header, 0, frame, 0, h);
                Buffer.BlockCopy(payload, 0, frame, h, count);
                stream.Write(frame, 0, frame.Length);
                stream.Flush();
            }
        }

        /// <summary>
        /// Next text or binary message. Pings are answered, pongs skipped. Returns null when
        /// the server closed the connection.
        /// </summary>
        public byte[] Receive(out int opcode)
        {
            opcode = 0;
            MemoryStream message = null;
            int messageOp = 0;
            while (true)
            {
                int b0 = stream.ReadByte();
                int b1 = stream.ReadByte();
                if (b0 < 0 || b1 < 0) { closed = true; return null; }
                bool fin = (b0 & 0x80) != 0;
                int op = b0 & 0x0F;
                bool masked = (b1 & 0x80) != 0;
                long len = b1 & 0x7F;
                if (len == 126) len = (ReadByteOrThrow() << 8) | ReadByteOrThrow();
                else if (len == 127)
                {
                    len = 0;
                    for (int i = 0; i < 8; i++) len = (len << 8) | (uint)ReadByteOrThrow();
                }
                if (len > 16 * 1024 * 1024) throw new IOException("WebSocket frame too large");
                byte[] mask = masked ? ReadExactly(4) : null;
                byte[] payload = ReadExactly((int)len);
                if (mask != null)
                    for (int i = 0; i < payload.Length; i++) payload[i] ^= mask[i & 3];

                switch (op)
                {
                    case OpPing:
                        SendFrame(OpPong, payload, 0, payload.Length);
                        continue;
                    case OpPong:
                        continue;
                    case OpClose:
                        try { SendFrame(OpClose, new byte[0], 0, 0); } catch (Exception) { }
                        closed = true;
                        return null;
                    case 0: // continuation
                        if (message == null) throw new IOException("WebSocket: unexpected continuation frame");
                        message.Write(payload, 0, payload.Length);
                        break;
                    default:
                        message = new MemoryStream();
                        messageOp = op;
                        message.Write(payload, 0, payload.Length);
                        break;
                }
                if (fin && message != null)
                {
                    opcode = messageOp;
                    return message.ToArray();
                }
            }
        }

        public string ReceiveText()
        {
            while (true)
            {
                int op;
                byte[] data = Receive(out op);
                if (data == null) return null;
                if (op == OpText) return Encoding.UTF8.GetString(data);
                // The server never sends binary data to clients; ignore it.
            }
        }

        private int ReadByteOrThrow()
        {
            int b = stream.ReadByte();
            if (b < 0) throw new EndOfStreamException();
            return b;
        }

        private byte[] ReadExactly(int count)
        {
            var buf = new byte[count];
            int got = 0;
            while (got < count)
            {
                int n = stream.Read(buf, got, count - got);
                if (n <= 0) throw new EndOfStreamException();
                got += n;
            }
            return buf;
        }

        public void Dispose()
        {
            if (!closed)
            {
                try { SendFrame(OpClose, new byte[] { 0x03, 0xE8 }, 0, 2); } catch (Exception) { }
                closed = true;
            }
            try { stream.Close(); } catch (Exception) { }
        }
    }
}
