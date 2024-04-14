﻿namespace Cryptography;

public abstract class BlockCipher : Cipher<byte[]>
{
    protected override void ProcessFile(string pathFrom, string pathTo, ProcessMethod processMethod)
    {
        using var reader = new BinaryReader(new FileStream(pathFrom, FileMode.Open));
        using var writer = new BinaryWriter(new FileStream(pathTo, FileMode.Create));

        Func<byte[], byte[]>? processBuf = processMethod switch
        {
            ProcessMethod.Encrypt => Encrypt,
            ProcessMethod.Decrypt => Decrypt,
            _ => null
        };
        if (processBuf is null)
        {
            throw new ArgumentException("Invalid proccess method", nameof(processMethod));
        }

        ProcessingFile(reader, writer, processBuf);
    }

    protected virtual void ProcessingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], byte[]> processBuf)
    {
        const int kDefaultBufSize = 1024;
        var buf = new byte[kDefaultBufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, kDefaultBufSize)) > 0)
        {
            writer.Write(processBuf(buf[..bytesRead]));
        }
    }
}
