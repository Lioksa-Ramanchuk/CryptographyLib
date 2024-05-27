namespace CryptographyLib;

using System.Numerics;
using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

public class ElGamalSignature(HashAlgorithm hasher, BigInteger p, BigInteger g, BigInteger x) : StringSigner<(BigInteger a, BigInteger b)>
{
    private readonly Random _rand = new();
    private readonly BigInteger y = BigInteger.ModPow(g, x, p);

    public HashAlgorithm Hasher { get; set; } = hasher;

    public override (BigInteger a, BigInteger b) Sign(byte[] data)
    {
        var m = p - 1;
        var k = _rand.GenerateCoprime(m, m);
        var a = BigInteger.ModPow(g, k, p);
        var h = new BigInteger(Hasher.ComputeHash(data), true) % m;
        var kInversed = Arithmetic.ModInverse(k, m);
        var b = kInversed * (h - x * a % m + m) % m;
        return (a, b);
    }

    public override bool VerifySignature(byte[] data, (BigInteger a, BigInteger b) signature)
    {
        var (a, b) = signature;
        var h = new BigInteger(Hasher.ComputeHash(data), true) % (p - 1);
        var ya = BigInteger.ModPow(y, a, p);
        var ab = BigInteger.ModPow(a, b, p);
        var gh = BigInteger.ModPow(g, h, p);
        return (ya * ab % p) == gh;
    }
}