namespace CryptographyLib;

using System.Numerics;

public class RSA(BigInteger p, BigInteger q, BigInteger e) : AsymmetricCipher<BigInteger>
{
    private readonly BigInteger n = p * q;
    private readonly BigInteger d = Arithmetic.ModInverse(e, (p - 1) * (q - 1));

    public override BigInteger[] Encrypt(byte[] text)
    {
        return [..text.Select(m => BigInteger.ModPow(new(m), e, n))];
    }

    public override byte[] Decrypt(BigInteger[] encrypted)
    {
        return [..encrypted.Select(c => (byte)BigInteger.ModPow(c, d, n))];
    }

    protected override void EncryptingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], BigInteger[]> encryptBuf, int bufSize = 1024)
    {
        var buf = new byte[bufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, bufSize)) > 0)
        {
            foreach (var c in encryptBuf(buf[..bytesRead]))
            {
                writer.Write(c.GetByteCount());
                writer.Write(c.ToByteArray());
            }
        }
    }

    protected override void DecryptingFile(BinaryReader reader, BinaryWriter writer, Func<BigInteger[], byte[]> decryptBigIntegers)
    {
        const int kMaxBlockSize = 1024;
        int currentSize = 0;
        List<BigInteger> bis = [];

        while (reader.BaseStream.Position != reader.BaseStream.Length)
        {
            var cSize = reader.ReadInt32();
            BigInteger c = new(reader.ReadBytes(cSize));

            if (currentSize + cSize > kMaxBlockSize)
            {
                writer.Write(decryptBigIntegers([.. bis]));
                bis = [];
                currentSize = 0;
            }

            bis.Add(c);
            currentSize += cSize;
        }

        writer.Write(decryptBigIntegers([.. bis]));
    }
}