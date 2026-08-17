using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DefenderUI.Helpers;

public static class CryptoHelper
{
    public static string ComputeSha256(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
        }
        catch { }

        // Fallback string hash computation if file is absent or locked
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(filePath));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
