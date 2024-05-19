namespace Cryptography;

using System.Numerics;
using SysCryptography = System.Security.Cryptography;

public static class Arithmetic
{
    public static int GCD(int a, params int[] nums)
    {
        var result = a;
        for (int i = 0; i < nums.Length; ++i)
        {
            a = result;
            var b = nums[i];
            while (a != 0 && b != 0)
            {
                if (a > b)
                {
                    a %= b;
                }
                else
                {
                    b %= a;
                }
            }
            result = a | b;
        }

        return result;
    }

    public static (int gcd, int x, int y) ExtendedGCD(int a, int b)
    {
        int x = 0, y = 1;   // b = a*x + b*y
        int u = 1, v = 0;   // a = a*u + b*v

        while (a != 0)
        {
            // b = a*q + r
            var (q, r) = (b / a, b % a);

            // a*x + b*y = b
            // a*u + b*v = a  | * -q
            // a * (x - u*q) + b * (y - v*q) = r
            var (m, n) = (x - u * q, y - v * q);
            (b, a) = (a, r);
            (x, y) = (u, v);
            (u, v) = (m, n);
        }
        return (b, x, y);
    }

    public static (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGCD(BigInteger a, BigInteger b)
    {
        BigInteger x = 0, y = 1;
        BigInteger u = 1, v = 0;

        while (a != 0)
        {
            var (q, r) = (b / a, b % a);
            var (m, n) = (x - u * q, y - v * q);
            (b, a) = (a, r);
            (x, y) = (u, v);
            (u, v) = (m, n);
        }
        return (b, x, y);
    }

    public static BigInteger ModInverse(BigInteger a, BigInteger n)
    {
        return (ExtendedGCD(a, n).x % n + n) % n;
    }

    public static bool IsPrime(int num)
    {
        if (num < 2)
        {
            return false;
        }

        if (num % 2 == 0)
        {
            return num == 2;
        }

        for (int i = 3; i * i <= num; i += 2)
        {
            if (num % i == 0)
            {
                return false;
            }
        }

        return true;
    }
    public static bool IsPrime(BigInteger num)
    {
        if (num < 2)
        {
            return false;
        }

        if (num % 2 == 0)
        {
            return num == 2;
        }

        for (BigInteger i = 3; i * i <= num; i += 2)
        {
            if (num % i == 0)
            {
                return false;
            }
        }

        return true;
    }

    public static IEnumerable<int>? GetPrimesBetween(int min, int max)
    {
        if (max < min || min < 0)
        {
            return null;
        }
        return Enumerable.Range(min, max - min + 1).Where(IsPrime);
    }

    public static List<int> GetDivisors(int num)
    {
        if (num < 0)
        {
            num = -num;
        }

        if (num < 2)
        {
            return [num];
        }

        List<int> divisors = [];
        for (int divisor = 2; num > 1; ++divisor)
        {
            while (num % divisor == 0)
            {
                divisors.Add(divisor);
                num /= divisor;
            }
        }

        return divisors;
    }

    public static BigInteger[] GenerateSuperincreasingSequence(int n, int minBits = 100)
    {
        Random rand = new();
        var seq = new BigInteger[n];
        BigInteger sum = 0;
        byte[] randomBytes;
        var delta = (double)minBits / n;
        for (int i = 0; i < n; ++i)
        {
            randomBytes = new byte[(int)Math.Ceiling(delta * (i + 1) / 8)];
            rand.NextBytes(randomBytes);
            seq[i] = sum + 1 + new BigInteger(randomBytes, true);
            sum += seq[i];
        }
        if (seq[n - 1].GetBitLength() < minBits)
        {
            seq[n - 1] += BigInteger.Pow(2, minBits - 1);
        }
        return seq;
    }

    public static BigInteger[] GenerateNormalSequence(BigInteger[] superincreasingSequence, BigInteger a, BigInteger n)
    {
        if (n <= superincreasingSequence.Aggregate((a, b) => a + b))
        {
            throw new ArgumentException("n needs to be greater than superincreasing sequence elements sum.", nameof(n));
        }
        if (BigInteger.GreatestCommonDivisor(a, n) != 1)
        {
            throw new ArgumentException("a needs to be coprime with n.", nameof(a));
        }
        return superincreasingSequence.Select(d => d * a % n).ToArray();
    }

    public static BigInteger NextBigInteger(this Random rand, BigInteger lowerBound, BigInteger upperBound)
    {
        if (lowerBound >= upperBound)
        {
            throw new ArgumentException("Lower bound must be less than upper bound.");
        }
        BigInteger range = upperBound - lowerBound;
        byte[] bytes = range.ToByteArray();
        rand.NextBytes(bytes);
        var randomBigInt = new BigInteger(bytes, true) % range;
        return randomBigInt + lowerBound;
    }

    public static BigInteger GenerateCoprime(this Random rand, BigInteger p, BigInteger upperBound)
    {
        if (p <= 2)
        {
            throw new ArgumentException("Parameter p must be greater than 2", nameof(p));
        }
        if (upperBound <= 2)
        {
            throw new ArgumentException("upperBound must be greater than 2", nameof(upperBound));
        }

        BigInteger result;
        var bytes = new byte[upperBound.GetByteCount()];
        do
        {
            rand.NextBytes(bytes);
            result = new BigInteger(bytes, true) % upperBound;
        }
        while (BigInteger.GreatestCommonDivisor(result, p) != 1 || result < 2);

        return result;
    }
}