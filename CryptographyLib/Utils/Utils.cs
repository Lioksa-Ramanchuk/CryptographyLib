namespace CryptographyLib.Utils;

using System.Diagnostics;
using System.Text;

public static class Utils
{
    public static void PrintFileHead(string path, Encoding encoding, int nLines = 3)
    {
        var consoleOutputEncoding = Console.OutputEncoding;
        Console.OutputEncoding = encoding;
        using StreamReader sr = new(path, encoding);
        string? line = null;
        for (int i = 0; i < nLines; i++)
        {
            line = sr.ReadLine();
            if (line is null) { break; }
            Console.WriteLine(line);
        }
        if (line is not null)
        {
            Console.WriteLine("...");
        }
        Console.OutputEncoding = consoleOutputEncoding;
    }

    public static void TraceExecutionTime(Action action, Func<Stopwatch, string>? format = null)
    {
        var watch = Stopwatch.StartNew();
        action();
        watch.Stop();
        format ??= w => $"| {w.ElapsedMilliseconds} ms";
        Console.WriteLine(format(watch));
    }
}