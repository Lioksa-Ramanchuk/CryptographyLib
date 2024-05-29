namespace CryptographyLib;

using System.Collections;
using System.Collections.Generic;
using System.Numerics;

public class RSAGenerator(BigInteger p, BigInteger q, BigInteger e, BigInteger x0)
    : IEnumerable<BigInteger>
{
    private readonly BigInteger n = BigInteger.Multiply(p, q);

    public IEnumerator<BigInteger> GetEnumerator()
    {
        while (true)
        {
            x0 = BigInteger.ModPow(x0, e, n);
            yield return x0;
        }
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public void ValidateState()
    {
        if (!Arithmetic.IsPrime(p) || !Arithmetic.IsPrime(q))
        {
            throw new ArgumentException("p and q must be prime numbers.");
        }

        if (n != BigInteger.Multiply(p, q))
        {
            throw new ArgumentException("n must be the product of p and q.");
        }

        if (BigInteger.GreatestCommonDivisor(e, BigInteger.Multiply(p - 1, q - 1)) != 1)
        {
            throw new ArgumentException("e must be coprime with (p-1)*(q-1).");
        }
    }
}