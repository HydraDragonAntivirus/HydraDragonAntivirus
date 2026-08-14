using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.WriteLine("ThemidaUnpacker (Magicmida x64 port)");

        if (args.Length < 1 || (args[0] != "/unpack" && args[0] != "-unpack" && args[0] != "--unpack"))
        {
            Console.WriteLine("Usage: ThemidaUnpacker /unpack <filename>");
            return 1;
        }

        string file = args[1];
        if (!File.Exists(file))
        {
            Console.WriteLine($"File not found: {file}");
            return 1;
        }

        int ts = Utils.GetPETimestamp(file);
        Console.WriteLine($"Target timestamp: {ts:X8}");

        try
        {
            var dbg = new Themida64(Path.GetFullPath(file), "");
            dbg.Run();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fatal: {ex.Message}");
            return 1;
        }

        return 0;
    }
}
