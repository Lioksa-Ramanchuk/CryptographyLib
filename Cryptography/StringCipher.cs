namespace Cryptography;

public abstract class StringCipher : Cipher<string, string>
{
    protected override void ProcessFile(string pathFrom, string pathTo, Mode mode)
    {
        using var reader = new StreamReader(pathFrom);
        using var writer = new StreamWriter(pathTo);

        Func<string, string>? processLine = mode switch
        {
            Mode.Encryption => Encrypt,
            Mode.Decryption => Decrypt,
            _ => null
        };
        if (processLine is null)
        {
            throw new ArgumentException("Invalid cipher mode.", nameof(mode));
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