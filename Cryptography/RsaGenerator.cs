namespace Cryptography;

using System.Collections;
using System.Collections.Generic;
using System.Numerics;

public class RsaGenerator(BigInteger p, BigInteger q, BigInteger e, BigInteger x0)
    : IEnumerable<BigInteger>
{
    public BigInteger Q { get; } = q;
    public BigInteger P { get; } = p;
    public BigInteger E { get; } = e;
    public BigInteger N { get; } = BigInteger.Multiply(p, q);
    public BigInteger X0 { get; set; } = x0;

    public IEnumerator<BigInteger> GetEnumerator()
    {
        while (true)
        {
            X0 = BigInteger.ModPow(X0, E, N);
            yield return X0;
        }
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public void ValidateState()
    {
        if (!Arithmetic.IsPrime(P) || !Arithmetic.IsPrime(Q))
        {
            throw new ArgumentException("p and q must be prime numbers.");
        }

        if (N != BigInteger.Multiply(P, Q))
        {
            throw new ArgumentException("n must be the product of p and q.");
        }

        if (BigInteger.GreatestCommonDivisor(E, BigInteger.Multiply(P - 1, Q - 1)) != 1)
        {
            throw new ArgumentException("e must be coprime with (p-1)*(q-1).");
        }
    }
}