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
        public static Stream Connect(string host, int port, int timeoutMs, out TcpClient tcp)
        {
            tcp = new TcpClient();
            tcp.ReceiveTimeout = timeoutMs;
            tcp.SendTimeout = timeoutMs;
            tcp.NoDelay = true;
            tcp.Connect(host, port);
            NetworkStream ns = tcp.GetStream();
            ns.ReadTimeout = timeoutMs;
            ns.WriteTimeout = timeoutMs;
            var protocol = new TlsClientProtocol(ns, new SecureRandom());
            protocol.Connect(new Client(host, TrustStore.Roots));
            return protocol.Stream;
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
