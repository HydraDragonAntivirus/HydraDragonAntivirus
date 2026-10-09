using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;

namespace VirusKov.ReactOS
{
    public sealed class FileJob
    {
        public string Path;
        public string Sha256; // lower-case hex
        public long Size;
    }

    public sealed class ScanResult
    {
        public string Path;
        public string Sha256;
        public long Size;
        /// <summary>malicious, suspicious, clean, possible_clean, unknown or error.</summary>
        public string Verdict = "unknown";
        public string Threat = "";
        public string Detail = "";
        public string Source = "";

        public bool IsThreat
        {
            get { return Verdict == "malicious" || Verdict == "suspicious"; }
        }
    }

    /// <summary>
    /// Talks to the VirusKov cloud with the same WebSocket protocol as Multron Win Cleaner
    /// (protocol version 3): hello, "check" batches of hashes, and "scan" + raw binary
    /// frames only for files the server does not know yet. Synchronous and single
    /// threaded on purpose: old machines, few files at a time, simple to reason about.
    /// </summary>
    public sealed class CloudClient : IDisposable
    {
        private const int ProtocolVersion = 3;
        private const int ChunkSize = 256 * 1024;
        private const int TimeoutMs = 120000;

        private readonly Settings settings;
        private TcpClient tcp;
        private WebSocketClient ws;
        private long nextId;

        public int MaxMB = 100;
        public int CheckBatch = 100;

        public CloudClient(Settings settings)
        {
            this.settings = settings;
        }

        public bool Connected
        {
            get { return ws != null; }
        }

        public void Connect()
        {
            var uri = new Uri(settings.ServerUrl);
            Stream stream;
            int port;
            if (uri.Scheme == "ws")
            {
                // Unencrypted only for a server on this computer (testing), like Multron Win Cleaner.
                if (!uri.IsLoopback)
                    throw new InvalidOperationException("Unencrypted ws:// addresses are only allowed for a server on this PC (localhost). Use wss://.");
                port = uri.Port > 0 ? uri.Port : 80;
                tcp = new TcpClient();
                tcp.ReceiveTimeout = tcp.SendTimeout = TimeoutMs;
                tcp.Connect(uri.Host, port);
                stream = tcp.GetStream();
            }
            else if (uri.Scheme == "wss")
            {
                port = uri.IsDefaultPort || uri.Port <= 0 ? 443 : uri.Port;
                stream = SecureChannel.Connect(uri.Host, port, TimeoutMs, out tcp);
            }
            else
                throw new InvalidOperationException("The server address must start with wss://.");
            ws = new WebSocketClient(stream);
            ws.Handshake(uri.IsDefaultPort ? uri.Host : uri.Host + ":" + port, uri.PathAndQuery);

            var hello = new Dictionary<string, object>();
            hello["type"] = "hello";
            hello["version"] = ProtocolVersion;
            hello["client"] = AppInfo.ClientName;
            hello["token"] = settings.Token ?? "";
            ws.SendText(Json.Serialize(hello));

            object reply = ReadMessage();
            string type = Json.GetString(reply, "type");
            if (type == "error")
                throw new IOException("Server: " + Json.GetString(reply, "message"));
            if (type != "hello_ok")
                throw new IOException("Unexpected answer from the server: " + type);
            if (Json.GetLong(reply, "version", 2) < 3)
                throw new IOException("The server is too old for this client.");
            MaxMB = (int)Json.GetLong(reply, "maxMB", MaxMB);
            CheckBatch = Math.Max(1, (int)Json.GetLong(reply, "checkBatch", CheckBatch));
        }

        private object ReadMessage()
        {
            string text = ws.ReceiveText();
            if (text == null)
                throw new IOException("The server closed the connection.");
            return Json.Parse(text);
        }

        /// <summary>
        /// Verdicts for files: hashes first, upload only what the server asks for.
        /// <paramref name="progress"/> gets (done, total); <paramref name="cancel"/> stops early.
        /// </summary>
        public List<ScanResult> Scan(IList<FileJob> jobs, Action<int, int> progress, Func<bool> cancel)
        {
            var results = new List<ScanResult>();
            int done = 0;
            for (int start = 0; start < jobs.Count; start += CheckBatch)
            {
                if (cancel != null && cancel()) break;
                int end = Math.Min(jobs.Count, start + CheckBatch);
                var batch = new Dictionary<long, FileJob>();
                var items = new List<object>();
                for (int i = start; i < end; i++)
                {
                    FileJob j = jobs[i];
                    long id = Interlocked.Increment(ref nextId);
                    batch[id] = j;
                    var item = new Dictionary<string, object>();
                    item["id"] = id;
                    item["name"] = System.IO.Path.GetFileName(j.Path);
                    item["size"] = j.Size;
                    item["sha256"] = j.Sha256;
                    item["folder"] = FileFilter.NormalizeFolder(j.Path);
                    items.Add(item);
                }
                var check = new Dictionary<string, object>();
                check["type"] = "check";
                check["items"] = items;
                ws.SendText(Json.Serialize(check));

                // Answers come in any order: a result, need_upload or an error per id.
                var uploads = new List<long>();
                var open = new Dictionary<long, bool>();
                foreach (long id in batch.Keys) open[id] = true;
                while (open.Count > 0)
                {
                    object msg = ReadMessage();
                    string type = Json.GetString(msg, "type");
                    long id = Json.GetLong(msg, "id", 0);
                    if (type == "error" && id == 0)
                        throw new IOException("Server: " + Json.GetString(msg, "message"));
                    if (!open.ContainsKey(id)) continue;
                    open.Remove(id);
                    if (type == "need_upload")
                    {
                        uploads.Add(id);
                        continue;
                    }
                    results.Add(ToResult(batch[id], msg));
                    done++;
                    if (progress != null) progress(done, jobs.Count);
                }

                foreach (long id in uploads)
                {
                    if (cancel != null && cancel()) break;
                    results.Add(Upload(id, batch[id]));
                    done++;
                    if (progress != null) progress(done, jobs.Count);
                }
            }
            return results;
        }

        private ScanResult Upload(long id, FileJob job)
        {
            var r = new ScanResult { Path = job.Path, Sha256 = job.Sha256, Size = job.Size };
            if (job.Size > (long)MaxMB * 1024 * 1024)
            {
                r.Verdict = "error";
                r.Detail = "File larger than the server limit (" + MaxMB + " MB)";
                return r;
            }
            var scan = new Dictionary<string, object>();
            scan["type"] = "scan";
            scan["id"] = id;
            scan["name"] = System.IO.Path.GetFileName(job.Path);
            scan["size"] = job.Size;
            scan["sha256"] = job.Sha256;
            scan["folder"] = FileFilter.NormalizeFolder(job.Path);
            ws.SendText(Json.Serialize(scan));

            // The server either answers from its cache (result), refuses (error) or asks for the bytes.
            while (true)
            {
                object msg = ReadMessage();
                string type = Json.GetString(msg, "type");
                long mid = Json.GetLong(msg, "id", 0);
                if (type == "error" && mid == 0)
                    throw new IOException("Server: " + Json.GetString(msg, "message"));
                if (mid != id) continue;
                if (type == "send_file") break;
                return ToResult(job, msg);
            }

            using (var fs = new FileStream(job.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, ChunkSize))
            {
                var buf = new byte[ChunkSize];
                long sent = 0;
                while (sent < job.Size)
                {
                    int n = fs.Read(buf, 0, (int)Math.Min(buf.Length, job.Size - sent));
                    if (n <= 0) throw new IOException("The file changed while it was being sent.");
                    ws.SendBinary(buf, 0, n);
                    sent += n;
                }
            }
            while (true)
            {
                object msg = ReadMessage();
                long mid = Json.GetLong(msg, "id", 0);
                string type = Json.GetString(msg, "type");
                if (type == "error" && mid == 0)
                    throw new IOException("Server: " + Json.GetString(msg, "message"));
                if (mid == id)
                    return ToResult(job, msg);
            }
        }

        /// <summary>ECS result (or error) from the server, as Multron Win Cleaner reads it.</summary>
        private static ScanResult ToResult(FileJob job, object msg)
        {
            var r = new ScanResult { Path = job.Path, Sha256 = job.Sha256, Size = job.Size };
            string type = Json.GetString(msg, "type");
            if (type != "result")
            {
                r.Verdict = "error";
                r.Detail = Json.GetString(msg, "message") ?? "Server error";
                return r;
            }
            r.Verdict = (Json.GetString(msg, "antivirus.verdict") ?? "unknown").ToLowerInvariant();
            r.Threat = Json.GetString(msg, "threat.indicator.name") ?? Json.GetString(msg, "rule.name") ?? "";
            r.Source = Json.GetString(msg, "antivirus.source") ?? "";
            var dets = Json.Get(msg, "antivirus.detections") as List<object>;
            if (dets != null && dets.Count > 0)
            {
                var parts = new List<string>();
                foreach (object d in dets)
                {
                    string name = Json.GetString(d, "name") ?? "";
                    string layer = Json.GetString(d, "layer") ?? "";
                    string details = Json.GetString(d, "details");
                    parts.Add(string.IsNullOrEmpty(details) ? name + " (" + layer + ")" : name + " (" + layer + "): " + details);
                }
                r.Detail = string.Join(" - ", parts.ToArray());
            }
            else
            {
                r.Detail = Json.GetString(msg, "antivirus.detail") ?? "";
            }
            if (r.Detail.Length == 0)
            {
                if (r.Verdict == "clean") r.Detail = "Clean (viruskov.com verified)";
                else if (r.Verdict == "possible_clean") r.Detail = "Possibly clean (very similar to a verified clean file)";
            }
            return r;
        }

        public void Dispose()
        {
            if (ws != null) { ws.Dispose(); ws = null; }
            if (tcp != null) { try { tcp.Close(); } catch (Exception) { } tcp = null; }
        }
    }
}
