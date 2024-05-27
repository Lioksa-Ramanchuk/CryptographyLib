namespace CryptographyLib;

using System.Numerics;

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

    public static bool IsPrime(int n)
    {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;

        for (int i = 5; i * i <= n; i += 6)
        {
            if (n % i == 0 || n % (i + 2) == 0)
            {
                return false;
            }
        }
        return true;
    }
    public static bool IsPrime(BigInteger n)
    {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;

        for (BigInteger i = 5; i * i <= n; i += 6)
        {
            if (n % i == 0 || n % (i + 2) == 0)
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

    public static List<int> GetPrimeFactors(int n)
    {
        List<int> s = [];
        if (n < 0) n = -n;
        if (n < 2) return [n];
        while (n % 2 == 0)
        {
            s.Add(2);
            n /= 2;
        }
        while (n % 3 == 0)
        {
            s.Add(3);
            n /= 3;
        }
        for (int d = 5; n > 1; d += 6)
        {
            while (n % d == 0)
            {
                s.Add(d);
                n /= d;
            }
            while (n % (d + 2) == 0)
            {
                s.Add(d + 2);
                n /= d + 2;
            }
        }
        return s;
    }
    public static List<BigInteger> GetPrimeFactors(BigInteger n)
    {
        List<BigInteger> s = [];
        if (n < 0) n = -n;
        if (n < 2) return [n];
        while (n % 2 == 0)
        {
            s.Add(2);
            n /= 2;
        }
        while (n % 3 == 0)
        {
            s.Add(3);
            n /= 3;
        }
        for (BigInteger d = 5; n > 1; d += 6)
        {
            while (n % d == 0)
            {
                s.Add(d);
                n /= d;
            }
            while (n % (d + 2) == 0)
            {
                s.Add(d + 2);
                n /= d + 2;
            }
        }
        return s;
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

    public static BigInteger GeneratePrimitiveRoot(BigInteger p, Random rand, long maxAttempts = 999_999)
    {
        if (!IsPrime(p))
        {
            throw new ArgumentException($"{nameof(p)} must be prime.");
        }
        var phi = p - 1;
        var factors = GetPrimeFactors(phi);

        while (maxAttempts-- > 0)
        {
            var g = rand.NextBigInteger(2, p - 1);
            bool isPrimitiveRoot = true;
            foreach (var f in factors)
            {
                if (BigInteger.ModPow(g, phi / f, p) == 1)
                {
                    isPrimitiveRoot = false;
                    break;
                }
            }
            if (isPrimitiveRoot) return g;
        }
        throw new ArgumentException($"No primitive root for {nameof(p)} found.", nameof(p));
    }
}