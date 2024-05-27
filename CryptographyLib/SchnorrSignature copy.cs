namespace CryptographyLib;

using System;
using System.Numerics;
using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

public class SchnorrSignature : StringSigner<(BigInteger h, BigInteger b)>
{
    private readonly Random _rand = new();

    public SchnorrSignature(HashAlgorithm hasher, BigInteger p, BigInteger q, BigInteger g, BigInteger x)
    {
        Hasher = hasher;
        P = p;
        Q = q;
        G = g;
        X = x;
        GInversed = Arithmetic.ModInverse(g, p);
        Y = BigInteger.ModPow(GInversed, x, p);
    }

    public BigInteger P { get; }
    public BigInteger Q { get; }
    public BigInteger G { get; }
    public BigInteger GInversed { get; }
    public BigInteger X { get; }
    public BigInteger Y { get; }
    public HashAlgorithm Hasher { get; set; }

    public override (BigInteger h, BigInteger b) Sign(byte[] data)
    {
        var k = _rand.NextBigInteger(1, Q);
        var a = BigInteger.ModPow(G, k, P);
        var h = new BigInteger(Hasher.ComputeHash([.. data, .. a.ToByteArray()]), true);
        var b = (k + X * h) % Q;
        return (h, b);
    }

    public override bool VerifySignature(byte[] data, (BigInteger h, BigInteger b) signature)
    {
        var (h, b) = signature;
        var x = BigInteger.ModPow(G, b, P) * BigInteger.ModPow(Y, h, P) % P;
        return h == new BigInteger(Hasher.ComputeHash([..data, ..x.ToByteArray()]), true);
    }
}