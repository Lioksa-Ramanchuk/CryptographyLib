namespace Cryptography;

using System.Numerics;
using SysCryptography = System.Security.Cryptography;

public class RSASignature : StringSigner<BigInteger>
{
    private readonly Random _rand = new();
    private readonly BigInteger _n;
    private readonly BigInteger _e;
    private readonly BigInteger _d;

    public RSASignature(SysCryptography.HashAlgorithm hasher, BigInteger p, BigInteger q)
    {
        Hasher = hasher;
        _n = p * q;
        var phi = (p - 1) * (q - 1);
        _e = _rand.GenerateCoprime(phi, phi);
        _d = Arithmetic.ModInverse(_e, phi);
    }
    public SysCryptography.HashAlgorithm Hasher { get; set; }

    public override BigInteger Sign(byte[] data)
    {
        return BigInteger.ModPow(new BigInteger(Hasher.ComputeHash(data), true), _d, _n);
    }

    public override bool VerifySignature(byte[] data, BigInteger signature)
    {
        var h = new BigInteger(Hasher.ComputeHash(data), true) % _n;
        return h == BigInteger.ModPow(signature, _e, _n);
    }
}