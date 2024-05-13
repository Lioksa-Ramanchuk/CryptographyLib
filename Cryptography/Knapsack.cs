using System.Numerics;

namespace Cryptography;

public class Knapsack(BigInteger[] d, BigInteger a, BigInteger n) : AsymmetricCipher
{
    public BigInteger A { get; } = a;
    public BigInteger InversedA { get; } = Arithmetic.ModInverse(a, n);
    public BigInteger N { get; } = n;
    public BigInteger[] D { get; } = d;
    public BigInteger[] E { get; } = Arithmetic.GenerateNormalSequence(d, a, n);

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
                    encrypted[iByte] += E[^(iBit + 1)];
                }
            }
        }
        return encrypted;
    }

    public override byte[] Decrypt(BigInteger[] encrypted)
    {
        var weights = encrypted.Select(c => c * InversedA % N).ToArray();

        var decrypted = new byte[weights.Length];
        for (int iByte = 0; iByte < decrypted.Length; ++iByte)
        {
            decrypted[iByte] = 0;
            for (int iBit = 0; iBit < 8; ++iBit)
            {
                var subWeight = D[^(iBit + 1)];
                if (weights[iByte] >= subWeight)
                {
                    weights[iByte] -= subWeight;
                    decrypted[iByte] |= (byte)(1 << iBit);
                }
            }
        }
        return decrypted;
    }
}