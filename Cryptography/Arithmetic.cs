using System.Numerics;

namespace Cryptography;

public static class Arithmetic
{
    public static int GCD(int a, params int[] nums)
    {
        int result = a;
        for (int i = 0; i < nums.Length; ++i)
        {
            a = result;
            int b = nums[i];
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
}