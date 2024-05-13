using System.Numerics;

namespace Cryptography;

public abstract class AsymmetricCipher : Cipher<byte[], BigInteger[]>
{
    protected override void ProcessFile(string pathFrom, string pathTo, Mode mode)
    {
        using var reader = new BinaryReader(new FileStream(pathFrom, FileMode.Open));
        using var writer = new BinaryWriter(new FileStream(pathTo, FileMode.Create));

        switch (mode)
        {
            case Mode.Encryption:
                EncryptingFile(reader, writer, Encrypt);
                break;
            case Mode.Decryption:
                DecryptingFile(reader, writer, Decrypt);
                break;
            default:
                throw new ArgumentException("Invalid cipher mode.", nameof(mode));
        }
    }

    protected virtual void EncryptingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], BigInteger[]> encryptBuf)
    {
        const int kDefaultBufSize = 1024;
        var buf = new byte[kDefaultBufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, kDefaultBufSize)) > 0)
        {
            foreach (var item in encryptBuf(buf[..bytesRead]))
            {
                writer.Write(item.GetByteCount());
                writer.Write(item.ToByteArray());
            }
        }
    }

    protected virtual void DecryptingFile(BinaryReader reader, BinaryWriter writer, Func<BigInteger[], byte[]> decryptBigIntegers)
    {
        List<BigInteger> bis = [];
        while (reader.BaseStream.Position != reader.BaseStream.Length)
        {
            var size = reader.ReadInt32();
            bis.Add(new(reader.ReadBytes(size)));
        }
        writer.Write(decryptBigIntegers([.. bis]));
    }
}