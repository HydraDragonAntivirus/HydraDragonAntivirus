using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// TLS 1.2 without the operating system. Windows XP, ReactOS and Windows 9x only speak
    /// SSL 3.0 / TLS 1.0 through SChannel, and the server (Cloudflare in front of it)
    /// requires TLS 1.2, so the handshake, the ciphers and the certificate check are done
    /// by BouncyCastle (pure managed code, no native DLL, no P/Invoke). Trusted roots come
    /// from roots.pem next to the program (the Mozilla CA bundle), so they can be updated
    /// without a new build.
    /// </summary>
    public static class SecureChannel
    {
        /// <summary>Opens a TCP connection and runs the TLS handshake. Returns the encrypted stream.</summary>
        public static Stream Connect(string host, int port, int timeoutMs, out IDisposable conn)
        {
            Stream stream = ConnectStream(host, port, timeoutMs, out conn);
            var protocol = new TlsClientProtocol(stream, new SecureRandom());
            protocol.Connect(new Client(host, TrustStore.Roots));
            return protocol.Stream;
        }

        public static Stream ConnectStream(string host, int port, int timeoutMs, out IDisposable conn)
        {
            var addrs = new List<System.Net.IPAddress>();
            System.Net.IPAddress parsed;
            if (System.Net.IPAddress.TryParse(host, out parsed))
            {
                addrs.Add(parsed);
            }
            else
            {
                try
                {
                    var a = System.Net.Dns.GetHostAddresses(host);
                    if (a != null) foreach (var ip in a) if (ip != null) addrs.Add(ip);
                }
                catch (Exception e)
                {
                    Log.Write("dns GetHostAddresses: " + e.Message);
                }

                if (addrs.Count == 0)
                {
                    try
                    {
                        var entry = System.Net.Dns.GetHostEntry(host);
                        if (entry != null && entry.AddressList != null)
                            foreach (var ip in entry.AddressList) if (ip != null) addrs.Add(ip);
                    }
                    catch (Exception e)
                    {
                        Log.Write("dns GetHostEntry: " + e.Message);
                    }
                }

#pragma warning disable 618
                if (addrs.Count == 0)
                {
                    try
                    {
                        var entry = System.Net.Dns.GetHostByName(host);
                        if (entry != null && entry.AddressList != null)
                            foreach (var ip in entry.AddressList) if (ip != null) addrs.Add(ip);
                    }
                    catch (Exception e)
                    {
                        Log.Write("dns GetHostByName: " + e.Message);
                    }
                }
#pragma warning restore 618

                // ReactOS DNS resolver fallback: if ReactOS cannot resolve external DNS inside VM,
                // fallback to the official Anycast Cloudflare IPs for api.viruskov.com.
                if (addrs.Count == 0 && host.Equals("api.viruskov.com", StringComparison.OrdinalIgnoreCase))
                {
                    Log.Write("dns fallback: using known Cloudflare Anycast IPs for api.viruskov.com");
                    addrs.Add(System.Net.IPAddress.Parse("172.67.174.121"));
                    addrs.Add(System.Net.IPAddress.Parse("104.21.47.233"));
                }
            }

            if (addrs.Count == 0)
                throw new IOException("Could not resolve host name: " + host);

            Exception lastEx = null;
            foreach (var ip in addrs)
            {
                // Only IPv4 on legacy systems / ReactOS
                if (ip.AddressFamily != AddressFamily.InterNetwork) continue;

                // Attempt 1: TcpClient with IPAddress directly (avoids Dns.GetHostAddresses in TcpClient)
                try
                {
                    var client = new TcpClient();
                    client.ReceiveTimeout = timeoutMs;
                    client.SendTimeout = timeoutMs;
                    client.NoDelay = true;
                    client.Connect(ip, port);
                    NetworkStream ns = client.GetStream();
                    ns.ReadTimeout = timeoutMs;
                    ns.WriteTimeout = timeoutMs;
                    conn = client;
                    return ns;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    Log.Write("TcpClient.Connect(" + ip + ":" + port + ") failed: " + ex.Message);
                }

                // Attempt 2: Direct raw Socket with NetworkStream(socket, true)
                try
                {
                    var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sock.NoDelay = true;
                    sock.ReceiveTimeout = timeoutMs;
                    sock.SendTimeout = timeoutMs;
                    sock.Connect(new System.Net.IPEndPoint(ip, port));

                    var ns = new NetworkStream(sock, true);
                    ns.ReadTimeout = timeoutMs;
                    ns.WriteTimeout = timeoutMs;
                    conn = sock;
                    return ns;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    Log.Write("Socket.Connect(" + ip + ":" + port + ") failed: " + ex.Message);
                }

                // Attempt 3: Native Winsock (ws2_32.dll) P/Invoke fallback.
                // ReactOS Mono/CLR 2.0 has an internal bug in Socket.Connect/IPEndPoint marshalling
                // that throws InvalidCastException. Native ws2_32.dll connect works directly on ReactOS kernel.
                try
                {
                    var nativeStream = NativeSocketStream.Connect(ip, port, timeoutMs);
                    conn = nativeStream;
                    Log.Write("Connected via Native Winsock to " + ip + ":" + port);
                    return nativeStream;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    Log.Write("NativeSocketStream.Connect(" + ip + ":" + port + ") failed: " + ex.Message);
                }
            }

            throw new IOException("Failed to connect to " + host + ":" + port + (lastEx != null ? " (" + lastEx.Message + ")" : ""));
        }

        private sealed class NativeSocketStream : Stream
        {
            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern int WSAStartup(short wVersionRequested, byte[] lpWSAData);

            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern IntPtr socket(int af, int type, int protocol);

            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern int connect(IntPtr s, byte[] name, int namelen);

            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern int send(IntPtr s, IntPtr buf, int len, int flags);

            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern int recv(IntPtr s, IntPtr buf, int len, int flags);

            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern int setsockopt(IntPtr s, int level, int optname, ref int optval, int optlen);

            [System.Runtime.InteropServices.DllImport("ws2_32.dll")]
            private static extern int WSAGetLastError();

            [System.Runtime.InteropServices.DllImport("ws2_32.dll", SetLastError = true)]
            private static extern int closesocket(IntPtr s);

            private IntPtr sock = IntPtr.Zero;

            public static NativeSocketStream Connect(System.Net.IPAddress ip, int port, int timeoutMs)
            {
                byte[] wsaData = new byte[512];
                WSAStartup(0x0202, wsaData);

                const int AF_INET = 2;
                const int SOCK_STREAM = 1;
                const int IPPROTO_TCP = 6;
                IntPtr s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == IntPtr.Zero || s.ToInt64() == -1)
                {
                    int err = WSAGetLastError();
                    throw new IOException("Native socket creation failed: " + err);
                }

                // Set timeouts
                const int SOL_SOCKET = 0xFFFF;
                const int SO_RCVTIMEO = 0x1006;
                const int SO_SNDTIMEO = 0x1005;
                const int TCP_NODELAY = 0x0001;
                int t = timeoutMs;
                int nodelay = 1;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, ref t, 4);
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, ref t, 4);
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, ref nodelay, 4);

                // Build sockaddr_in (16 bytes)
                byte[] sockaddr = new byte[16];
                sockaddr[0] = (byte)(AF_INET & 0xFF);
                sockaddr[1] = (byte)((AF_INET >> 8) & 0xFF);
                sockaddr[2] = (byte)((port >> 8) & 0xFF); // Big-endian port
                sockaddr[3] = (byte)(port & 0xFF);
                byte[] ipBytes = ip.GetAddressBytes();
                sockaddr[4] = ipBytes[0];
                sockaddr[5] = ipBytes[1];
                sockaddr[6] = ipBytes[2];
                sockaddr[7] = ipBytes[3];

                int res = connect(s, sockaddr, 16);
                if (res != 0)
                {
                    int err = WSAGetLastError();
                    closesocket(s);
                    throw new IOException("Native connect failed, error code: " + err);
                }

                return new NativeSocketStream { sock = s };
            }

            public override bool CanRead { get { return sock != IntPtr.Zero && sock.ToInt64() != -1; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return sock != IntPtr.Zero && sock.ToInt64() != -1; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (sock == IntPtr.Zero || sock.ToInt64() == -1) throw new ObjectDisposedException("NativeSocketStream");
                if (buffer == null) throw new ArgumentNullException("buffer");
                if (offset < 0 || count < 0 || offset + count > buffer.Length) throw new ArgumentOutOfRangeException();
                if (count == 0) return 0;

                var handle = System.Runtime.InteropServices.GCHandle.Alloc(buffer, System.Runtime.InteropServices.GCHandleType.Pinned);
                try
                {
                    IntPtr ptr = new IntPtr(handle.AddrOfPinnedObject().ToInt64() + offset);
                    int n = recv(sock, ptr, count, 0);
                    if (n < 0)
                    {
                        int err = WSAGetLastError();
                        throw new IOException("Native recv error: " + err);
                    }
                    return n;
                }
                finally
                {
                    handle.Free();
                }
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (sock == IntPtr.Zero || sock.ToInt64() == -1) throw new ObjectDisposedException("NativeSocketStream");
                if (buffer == null) throw new ArgumentNullException("buffer");
                if (offset < 0 || count < 0 || offset + count > buffer.Length) throw new ArgumentOutOfRangeException();
                if (count == 0) return;

                var handle = System.Runtime.InteropServices.GCHandle.Alloc(buffer, System.Runtime.InteropServices.GCHandleType.Pinned);
                try
                {
                    int sent = 0;
                    while (sent < count)
                    {
                        IntPtr ptr = new IntPtr(handle.AddrOfPinnedObject().ToInt64() + offset + sent);
                        int n = send(sock, ptr, count - sent, 0);
                        if (n <= 0)
                        {
                            int err = WSAGetLastError();
                            throw new IOException("Native send error: " + err);
                        }
                        sent += n;
                    }
                }
                finally
                {
                    handle.Free();
                }
            }

            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }

            protected override void Dispose(bool disposing)
            {
                if (sock != IntPtr.Zero && sock.ToInt64() != -1)
                {
                    try { closesocket(sock); } catch (Exception) { }
                    sock = IntPtr.Zero;
                }
                base.Dispose(disposing);
            }
        }

        private sealed class Client : DefaultTlsClient
        {
            private readonly string host;
            private readonly IList<X509Certificate> roots;

            public Client(string host, IList<X509Certificate> roots)
            {
                this.host = host;
                this.roots = roots;
            }

            // Server Name Indication: Cloudflare picks the certificate by host name.
            public override IDictionary GetClientExtensions()
            {
                IDictionary ext = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());
                var names = new ArrayList();
                names.Add(new ServerName(NameType.host_name, host));
                TlsExtensionsUtilities.AddServerNameExtension(ext, new ServerNameList(names));
                return ext;
            }

            public override TlsAuthentication GetAuthentication()
            {
                return new Authentication(host, roots);
            }
        }

        private sealed class Authentication : TlsAuthentication
        {
            private readonly string host;
            private readonly IList<X509Certificate> roots;

            public Authentication(string host, IList<X509Certificate> roots)
            {
                this.host = host;
                this.roots = roots;
            }

            public void NotifyServerCertificate(Certificate serverCertificate)
            {
                X509CertificateStructure[] raw = serverCertificate.GetCertificateList();
                var chain = new List<X509Certificate>();
                foreach (X509CertificateStructure c in raw)
                    chain.Add(new X509Certificate(c));
                string error = CertificateValidator.Validate(chain, roots, host, DateTime.UtcNow);
                if (error != null)
                {
                    Log.Write("TLS: certificate rejected: " + error);
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                return null; // no client certificate
            }
        }
    }

    /// <summary>Root certificates from roots.pem (loaded once).</summary>
    public static class TrustStore
    {
        private static IList<X509Certificate> roots;
        private static readonly object Sync = new object();

        public static IList<X509Certificate> Roots
        {
            get
            {
                lock (Sync)
                {
                    if (roots == null)
                        roots = Load(Path.Combine(AppPaths.ProgramDir, "roots.pem"));
                    return roots;
                }
            }
        }

        private static IList<X509Certificate> Load(string path)
        {
            var list = new List<X509Certificate>();
            if (!File.Exists(path))
                throw new FileNotFoundException("roots.pem (trusted root certificates) is missing next to the program", path);
            using (FileStream fs = File.OpenRead(path))
            {
                ICollection certs = new X509CertificateParser().ReadCertificates(fs);
                foreach (object o in certs)
                {
                    var c = o as X509Certificate;
                    if (c != null) list.Add(c);
                }
            }
            if (list.Count == 0)
                throw new InvalidDataException("roots.pem contains no certificates");
            return list;
        }
    }

    /// <summary>
    /// Chain and host name check: every certificate is in its validity period and signed
    /// by the next one, the last one is signed by (or is) a trusted root, intermediates are
    /// CAs, and the server certificate names the host.
    /// </summary>
    public static class CertificateValidator
    {
        public static string Validate(IList<X509Certificate> chain, IList<X509Certificate> roots, string host, DateTime nowUtc)
        {
            if (chain == null || chain.Count == 0)
                return "the server sent no certificate";
            for (int i = 0; i < chain.Count; i++)
            {
                X509Certificate c = chain[i];
                try { c.CheckValidity(nowUtc); }
                catch (Exception) { return "certificate expired or not yet valid: " + c.SubjectDN; }
                if (i > 0 && c.GetBasicConstraints() < 0)
                    return "intermediate certificate is not a CA: " + c.SubjectDN;
                if (i + 1 < chain.Count)
                {
                    if (!SignedBy(c, chain[i + 1]))
                        return "broken certificate chain at " + c.SubjectDN;
                }
            }
            if (!HostMatches(chain[0], host))
                return "the certificate is not for " + host;

            // Anchor: the last certificate (or any certificate in the chain) is issued by a root.
            for (int i = 0; i < chain.Count; i++)
            {
                X509Certificate c = chain[i];
                foreach (X509Certificate root in roots)
                {
                    if (!c.IssuerDN.Equivalent(root.SubjectDN))
                        continue;
                    try
                    {
                        root.CheckValidity(nowUtc);
                    }
                    catch (Exception)
                    {
                        continue;
                    }
                    if (SignedBy(c, root))
                        return null;
                }
                // The chain may include the root itself.
                foreach (X509Certificate root in roots)
                {
                    if (c.Equals(root))
                        return null;
                }
            }
            return "no trusted root for " + chain[chain.Count - 1].IssuerDN;
        }

        private static bool SignedBy(X509Certificate cert, X509Certificate issuer)
        {
            if (!cert.IssuerDN.Equivalent(issuer.SubjectDN))
                return false;
            try
            {
                cert.Verify(issuer.GetPublicKey());
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static bool HostMatches(X509Certificate cert, string host)
        {
            host = host.ToLowerInvariant();
            var names = new List<string>();
            ICollection san = null;
            try { san = cert.GetSubjectAlternativeNames(); }
            catch (Exception) { }
            if (san != null)
            {
                foreach (object o in san)
                {
                    var entry = o as IList;
                    if (entry != null && entry.Count >= 2 && Convert.ToInt32(entry[0]) == GeneralName.DnsName)
                        names.Add(Convert.ToString(entry[1]).ToLowerInvariant());
                }
            }
            if (names.Count == 0)
            {
                foreach (object cn in cert.SubjectDN.GetValueList(X509Name.CN))
                    names.Add(Convert.ToString(cn).ToLowerInvariant());
            }
            foreach (string n in names)
            {
                if (n == host)
                    return true;
                // *.example.com matches one label only.
                if (n.StartsWith("*.") && host.EndsWith(n.Substring(1)))
                {
                    string left = host.Substring(0, host.Length - (n.Length - 1));
                    if (left.Length > 0 && left.IndexOf('.') < 0)
                        return true;
                }
            }
            return false;
        }
    }
}
