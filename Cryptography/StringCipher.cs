namespace Cryptography;

public abstract class StringCipher : Cipher<string>
{
    protected override void ProcessFile(string pathFrom, string pathTo, ProcessMethod processMethod)
    {
        File.Create(pathTo).Dispose();

        using var reader = new StreamReader(pathFrom);
        using var writer = new StreamWriter(pathTo);

        Func<string, string>? processLine = processMethod switch
        {
            ProcessMethod.Encrypt => Encrypt,
            ProcessMethod.Decrypt => Decrypt,
            _ => null
        };
        if (processLine is null)
        {
            throw new ArgumentException("Invalid proccess method", nameof(processMethod));
        }

        ProcessingFile(reader, writer, processLine);
    }

    protected virtual void ProcessingFile(StreamReader reader, StreamWriter writer, Func<string, string> processLine)
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            writer.WriteLine(processLine(line));
        }
    }
}
