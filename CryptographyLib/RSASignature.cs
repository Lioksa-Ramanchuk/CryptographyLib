namespace CryptographyLib;

using System.Numerics;
using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

public class RSASignature(HashAlgorithm hasher, BigInteger p, BigInteger q, BigInteger e) : StringSigner<BigInteger>
{
    private readonly BigInteger n = p * q;
    private readonly BigInteger d = Arithmetic.ModInverse(e, (p - 1) * (q - 1));

    public HashAlgorithm Hasher { get; set; } = hasher;

    public override BigInteger Sign(byte[] data)
    {
        return BigInteger.ModPow(new BigInteger(Hasher.ComputeHash(data), true), d, n);
    }

    public override bool VerifySignature(byte[] data, BigInteger signature)
    {
        var h = new BigInteger(Hasher.ComputeHash(data), true) % n;
        return h == BigInteger.ModPow(signature, e, n);
    }
}