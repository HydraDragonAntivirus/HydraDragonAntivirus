using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// Minimal JSON reader/writer. .NET 3.5 has no JSON parser that works on every target
    /// (System.Web.Extensions is missing on some ReactOS / dotnet9x installs), and the
    /// server messages are small, so a few hundred lines are enough.
    /// Objects become Dictionary&lt;string, object&gt;, arrays List&lt;object&gt;,
    /// numbers double, plus string, bool and null.
    /// </summary>
    public static class Json
    {
        public static object Parse(string text)
        {
            int i = 0;
            object v = ReadValue(text, ref i);
            SkipWs(text, ref i);
            if (i != text.Length)
                throw new FormatException("JSON: trailing characters at " + i);
            return v;
        }

        /// <summary>Value at a dotted path ("antivirus.verdict"), or null.</summary>
        public static object Get(object root, string path)
        {
            object cur = root;
            foreach (string part in path.Split('.'))
            {
                var d = cur as Dictionary<string, object>;
                if (d == null || !d.TryGetValue(part, out cur))
                    return null;
            }
            return cur;
        }

        public static string GetString(object root, string path)
        {
            object v = Get(root, path);
            if (v == null) return null;
            if (v is string) return (string)v;
            if (v is bool) return (bool)v ? "true" : "false";
            if (v is IConvertible)
            {
                try { return Convert.ToString(v, CultureInfo.InvariantCulture); }
                catch (Exception) { }
            }
            return v.ToString();
        }

        public static long GetLong(object root, string path, long fallback)
        {
            object v = Get(root, path);
            if (v == null) return fallback;
            if (v is long) return (long)v;
            if (v is int) return (int)v;
            if (v is double) return (long)(double)v;
            if (v is float) return (long)(float)v;
            if (v is decimal) return (long)(decimal)v;
            if (v is short) return (short)v;
            if (v is byte) return (byte)v;
            if (v is uint) return (uint)v;
            if (v is ulong) return (long)(ulong)v;
            if (v is IConvertible)
            {
                try { return Convert.ToInt64(v, CultureInfo.InvariantCulture); }
                catch (Exception) { }
            }
            if (v is string)
            {
                long l;
                if (long.TryParse((string)v, NumberStyles.Integer | NumberStyles.Float, CultureInfo.InvariantCulture, out l)) return l;
            }
            return fallback;
        }

        // ---------------- writer ----------------

        public static string Serialize(object value)
        {
            var sb = new StringBuilder();
            Write(sb, value);
            return sb.ToString();
        }

        private static void Write(StringBuilder sb, object v)
        {
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { WriteString(sb, (string)v); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is int || v is long || v is short || v is byte || v is uint || v is ulong)
            {
                sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture));
                return;
            }
            if (v is double || v is float || v is decimal)
            {
                sb.Append(Convert.ToDouble(v, CultureInfo.InvariantCulture).ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            var dict = v as IDictionary;
            if (dict != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (DictionaryEntry e in dict)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, Convert.ToString(e.Key, CultureInfo.InvariantCulture));
                    sb.Append(':');
                    Write(sb, e.Value);
                }
                sb.Append('}');
                return;
            }
            var list = v as IEnumerable;
            if (list != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object item in list)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Write(sb, item);
                }
                sb.Append(']');
                return;
            }
            WriteString(sb, v.ToString());
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        // ---------------- reader ----------------

        private static void SkipWs(string s, ref int i)
        {
            while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
        }

        private static object ReadValue(string s, ref int i)
        {
            SkipWs(s, ref i);
            if (i >= s.Length) throw new FormatException("JSON: unexpected end");
            char c = s[i];
            if (c == '{') return ReadObject(s, ref i);
            if (c == '[') return ReadArray(s, ref i);
            if (c == '"') return ReadString(s, ref i);
            if (c == 't' && string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (c == 'f' && string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (c == 'n' && string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            return ReadNumber(s, ref i);
        }

        private static Dictionary<string, object> ReadObject(string s, ref int i)
        {
            var d = new Dictionary<string, object>();
            i++; // {
            SkipWs(s, ref i);
            if (i < s.Length && s[i] == '}') { i++; return d; }
            while (true)
            {
                SkipWs(s, ref i);
                if (i >= s.Length || s[i] != '"') throw new FormatException("JSON: expected key at " + i);
                string key = ReadString(s, ref i);
                SkipWs(s, ref i);
                if (i >= s.Length || s[i] != ':') throw new FormatException("JSON: expected ':' at " + i);
                i++;
                d[key] = ReadValue(s, ref i);
                SkipWs(s, ref i);
                if (i >= s.Length) throw new FormatException("JSON: unexpected end in object");
                if (s[i] == ',') { i++; continue; }
                if (s[i] == '}') { i++; return d; }
                throw new FormatException("JSON: expected ',' or '}' at " + i);
            }
        }

        private static List<object> ReadArray(string s, ref int i)
        {
            var l = new List<object>();
            i++; // [
            SkipWs(s, ref i);
            if (i < s.Length && s[i] == ']') { i++; return l; }
            while (true)
            {
                l.Add(ReadValue(s, ref i));
                SkipWs(s, ref i);
                if (i >= s.Length) throw new FormatException("JSON: unexpected end in array");
                if (s[i] == ',') { i++; continue; }
                if (s[i] == ']') { i++; return l; }
                throw new FormatException("JSON: expected ',' or ']' at " + i);
            }
        }

        private static string ReadString(string s, ref int i)
        {
            var sb = new StringBuilder();
            i++; // opening quote
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw new FormatException("JSON: bad \\u escape");
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: throw new FormatException("JSON: bad escape \\" + e);
                }
            }
            throw new FormatException("JSON: unterminated string");
        }

        private static double ReadNumber(string s, ref int i)
        {
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (i == start) throw new FormatException("JSON: unexpected character '" + s[i] + "' at " + i);
            return double.Parse(s.Substring(start, i - start), NumberStyles.Float, CultureInfo.InvariantCulture);
        }
    }
}
