namespace CryptographyLib;

using System;
using System.Numerics;
using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

public class SchnorrSignature(HashAlgorithm hasher, BigInteger p, BigInteger q, BigInteger g, BigInteger x) : StringSigner<(BigInteger h, BigInteger b)>
{
    private readonly Random _rand = new();
    private readonly BigInteger y = BigInteger.ModPow(Arithmetic.ModInverse(g, p), x, p);

    public HashAlgorithm Hasher { get; set; } = hasher;

    public override (BigInteger h, BigInteger b) Sign(byte[] data)
    {
        var k = _rand.NextBigInteger(1, q);
        var a = BigInteger.ModPow(g, k, p);
        var h = new BigInteger(Hasher.ComputeHash([.. data, .. a.ToByteArray()]), true);
        var b = (k + x * h) % q;
        return (h, b);
    }

    public override bool VerifySignature(byte[] data, (BigInteger h, BigInteger b) signature)
    {
        var (h, b) = signature;
        var X = BigInteger.ModPow(g, b, p) * BigInteger.ModPow(y, h, p) % p;
        return h == new BigInteger(Hasher.ComputeHash([..data, ..X.ToByteArray()]), true);
    }
}