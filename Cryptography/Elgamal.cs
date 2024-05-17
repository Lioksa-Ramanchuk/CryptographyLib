using System.Numerics;

namespace Cryptography;

public class Elgamal(BigInteger p, BigInteger g, BigInteger x) : AsymmetricCipher<(BigInteger a, BigInteger b)>
{
    private readonly Random rand = new();

    public BigInteger P { get; } = p;
    public BigInteger G { get; } = g;
    public BigInteger X { get; } = x;
    public BigInteger Y { get; } = BigInteger.ModPow(g, x, p);

    public override (BigInteger a, BigInteger b)[] Encrypt(byte[] text)
    {
        var encoded = new List<(BigInteger a, BigInteger b)>(text.Length);

        if (!int.TryParse(P.ToString(), out int kUpperBound))
        {
            kUpperBound = int.MaxValue;
        }
        foreach (var b in text)
        {
            int k = rand.Next(1, kUpperBound);
            encoded.Add((
                    BigInteger.ModPow(G, k, P),
                    BigInteger.ModPow(Y, k, P) * (BigInteger)b
                ));
        }
        return [.. encoded];
    }

    public override byte[] Decrypt((BigInteger a, BigInteger b)[] encryptedText)
    {
        var decrypted = new List<byte>(encryptedText.Length);
        foreach (var (a, b) in encryptedText)
        {
            decrypted.Add((byte)(b * BigInteger.ModPow(a, P - X - 1, P) % P));
        }
        return [.. decrypted];
    }

    protected override void EncryptingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], (BigInteger a, BigInteger b)[]> encryptBuf, int bufSize = 1024)
    {
        var buf = new byte[bufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, bufSize)) > 0)
        {
            foreach (var (a, b) in encryptBuf(buf[..bytesRead]))
            {
                writer.Write(a.GetByteCount());
                writer.Write(a.ToByteArray());
                writer.Write(b.GetByteCount());
                writer.Write(b.ToByteArray());
            }
        }
    }

    protected override void DecryptingFile(BinaryReader reader, BinaryWriter writer, Func<(BigInteger a, BigInteger b)[], byte[]> decryptBigIntegersPairs)
    {
        const int kMaxBlockSize = 1024;
        int currentSize = 0;
        List<(BigInteger, BigInteger)> bis = [];
        while (reader.BaseStream.Position != reader.BaseStream.Length)
        {
            var aSize = reader.ReadInt32();
            BigInteger a = new(reader.ReadBytes(aSize));
            var bSize = reader.ReadInt32();
            BigInteger b = new(reader.ReadBytes(bSize));

            if (currentSize + aSize + bSize > kMaxBlockSize)
            {
                writer.Write(decryptBigIntegersPairs([.. bis]));
                bis = [];
                currentSize = 0;
            }
            bis.Add((a, b));
            currentSize += aSize + bSize;
        }
        writer.Write(decryptBigIntegersPairs([.. bis]));
    }
}
