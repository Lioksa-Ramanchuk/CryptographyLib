namespace Cryptography;

public abstract class ByteHasher : Hasher<byte[], byte[]>
{
    protected override void ProcessFile(string pathFrom, string pathTo)
    {
        using var reader = new BinaryReader(new FileStream(pathFrom, FileMode.Open));
        using var writer = new BinaryWriter(new FileStream(pathTo, FileMode.Create));

        ProcessingFile(reader, writer);
    }

    protected virtual void ProcessingFile(BinaryReader reader, BinaryWriter writer, int bufSize = 1024)
    {
        var buf = new byte[bufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, bufSize)) > 0)
        {
            writer.Write(Hash(buf[..bytesRead]));
        }
    }
}