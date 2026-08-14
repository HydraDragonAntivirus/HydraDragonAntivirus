namespace ThemidaUnpacker;

public enum LogType
{
    Info,
    Good,
    Warning,
    Fatal,
}

public static class Utils
{
    public static void Log(LogType t, string msg)
    {
        Console.WriteLine($"[{t}] {msg}");
    }

    public static string AccessViolationFlagToStr(byte flag)
    {
        return flag switch
        {
            0 => "Read",
            1 => "Write",
            8 => "Execute",
            _ => flag.ToString(),
        };
    }

    /// <summary>Pattern is a hex string where "??" bytes are wildcards. Returns offset or 0.</summary>
    public static int FindDynamic(string pattern, ReadOnlySpan<byte> buf)
    {
        if (pattern.Length < 2) return 0;
        var bytes = new List<byte>();
        var wild = new List<bool>();
        for (int i = 0; i + 1 < pattern.Length; i += 2)
        {
            string hex = pattern.Substring(i, 2);
            if (hex[0] == '?' || hex[1] == '?')
            {
                wild.Add(true);
                bytes.Add(0);
            }
            else
            {
                wild.Add(false);
                bytes.Add(Convert.ToByte(hex, 16));
            }
        }

        if (bytes.Count == 0 || bytes.Count > buf.Length) return 0;
        for (int i = 0; i <= buf.Length - bytes.Count; i++)
        {
            bool match = true;
            for (int j = 0; j < bytes.Count; j++)
            {
                if (!wild[j] && buf[i + j] != bytes[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return 0;
    }

    /// <summary>Pattern is a hex string. Returns offset or 0.</summary>
    public static int FindStatic(string pattern, ReadOnlySpan<byte> buf)
    {
        if (pattern.Length < 2) return 0;
        var bytes = new byte[pattern.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(pattern.Substring(i * 2, 2), 16);

        if (bytes.Length == 0 || bytes.Length > buf.Length) return 0;
        for (int i = 0; i <= buf.Length - bytes.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < bytes.Length; j++)
                if (buf[i + j] != bytes[j]) { match = false; break; }
            if (match) return i;
        }
        return 0;
    }

    public static string AnsiString(byte[] name)
    {
        int len = 0;
        while (len < name.Length && name[len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(name, 0, len);
    }

    public static int GetPETimestamp(string filename)
    {
        try
        {
            var fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var header = new byte[0x1000];
            fs.Read(header, 0, header.Length);
            fs.Dispose();

            int lfanew = BitConverter.ToInt32(header, 0x3C);
            if (lfanew > 0xF00) return 0;
            return BitConverter.ToInt32(header, lfanew + 8);
        }
        catch { return 0; }
    }

    public static uint GetWindowsBuildNumber()
    {
        var os = Environment.OSVersion;
        return (uint)os.Version.Build;
    }
}

public struct MemoryRegion
{
    public ulong Address;
    public ulong Size;

    public bool Contains(ulong addr)
    {
        return addr >= Address && addr < Address + Size;
    }
}