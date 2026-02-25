using System;
using System.Security.Cryptography;
using System.Text;

namespace HydraDragonClient.Security
{
    /// <summary>
    /// Cryptographic utilities for session security
    /// </summary>
    public static class CryptoProvider
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        /// <summary>
        /// Generate a random 6-digit session password
        /// </summary>
        public static string GenerateSessionPassword()
        {
            var bytes = new byte[4];
            Rng.GetBytes(bytes);
            var number = Math.Abs(BitConverter.ToInt32(bytes, 0)) % 1000000;
            return number.ToString("D6");
        }

        /// <summary>
        /// Hash a password using SHA-256
        /// </summary>
        public static string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Verify a password against a hash
        /// </summary>
        public static bool VerifyPassword(string password, string hash)
        {
            var computed = HashPassword(password);
            return string.Equals(computed, hash, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Check if an IP address is a LAN (private) address
        /// </summary>
        public static bool IsLanAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;
            
            // Handle localhost
            if (ipAddress == "127.0.0.1" || ipAddress == "::1" || ipAddress.ToLower() == "localhost")
                return true;

            var parts = ipAddress.Split('.');
            if (parts.Length != 4) return false;

            if (!byte.TryParse(parts[0], out var a) ||
                !byte.TryParse(parts[1], out var b) ||
                !byte.TryParse(parts[2], out var c) ||
                !byte.TryParse(parts[3], out var d))
                return false;

            // 10.0.0.0 - 10.255.255.255
            if (a == 10) return true;
            
            // 172.16.0.0 - 172.31.255.255
            if (a == 172 && b >= 16 && b <= 31) return true;
            
            // 192.168.0.0 - 192.168.255.255
            if (a == 192 && b == 168) return true;

            return false;
        }

        /// <summary>
        /// Generate a random AES-256 key
        /// </summary>
        public static byte[] GenerateAesKey()
        {
            var key = new byte[32];
            Rng.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Encrypt data using AES-256-CBC
        /// </summary>
        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            
            using var encryptor = aes.CreateEncryptor();
            var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
            
            // Prepend IV to encrypted data
            var result = new byte[16 + encrypted.Length];
            aes.IV.CopyTo(result, 0);
            encrypted.CopyTo(result, 16);
            
            return result;
        }

        /// <summary>
        /// Decrypt data using AES-256-CBC
        /// </summary>
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data.Length < 17) throw new ArgumentException("Invalid encrypted data");
            
            using var aes = Aes.Create();
            aes.Key = key;
            
            // Extract IV from data
            var iv = new byte[16];
            Array.Copy(data, 0, iv, 0, 16);
            aes.IV = iv;
            
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 16, data.Length - 16);
        }
    }
}
