using System.Numerics;

namespace CryptographyLib;

public class Knapsack(BigInteger[] d, BigInteger a, BigInteger n) : AsymmetricCipher<BigInteger>
{
    private readonly BigInteger _aInversed = Arithmetic.ModInverse(a, n);
    private readonly BigInteger[] e = Arithmetic.GenerateNormalSequence(d, a, n);

    public override BigInteger[] Encrypt(byte[] text)
    {
        var encrypted = new BigInteger[text.Length];
        for (int iByte = 0; iByte < text.Length; ++iByte)
        {
            encrypted[iByte] = 0;
            for (int iBit = 7; iBit >= 0; --iBit)
            {
                if ((text[iByte] & (1 << iBit)) != 0)
                {
                    encrypted[iByte] += e[^(iBit + 1)];
                }
            }
        }
        return encrypted;
    }

    public override byte[] Decrypt(BigInteger[] encrypted)
    {
        var weights = encrypted.Select(c => c * _aInversed % n).ToArray();

        var decrypted = new byte[weights.Length];
        for (int iByte = 0; iByte < decrypted.Length; ++iByte)
        {
            decrypted[iByte] = 0;
            for (int iBit = 0; iBit < 8; ++iBit)
            {
                var subWeight = d[^(iBit + 1)];
                if (weights[iByte] >= subWeight)
                {
                    weights[iByte] -= subWeight;
                    decrypted[iByte] |= (byte)(1 << iBit);
                }
            }
        }
        return decrypted;
    }

    protected override void EncryptingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], BigInteger[]> encryptBuf, int bufSize = 1024)
    {
        var buf = new byte[bufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, bufSize)) > 0)
        {
            foreach (var item in encryptBuf(buf[..bytesRead]))
            {
                writer.Write(item.GetByteCount());
                writer.Write(item.ToByteArray());
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
            var size = reader.ReadInt32();
            if (currentSize + size > kMaxBlockSize)
            {
                writer.Write(decryptBigIntegers([.. bis]));
                bis = [];
                currentSize = 0;
            }
            bis.Add(new(reader.ReadBytes(size)));
            currentSize += size;
        }
        writer.Write(decryptBigIntegers([.. bis]));
    }
}