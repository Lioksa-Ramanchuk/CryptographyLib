namespace Cryptography.Utils;

public class BitArray : List<bool>
{
    public BitArray(BitArray ba) : base(ba) { }
    public BitArray(int capacity)
    {
        AddRange(new bool[capacity]);
    }
    public BitArray(IEnumerable<bool> bits) : base(bits) { }
    public BitArray(byte[] bytes)
    {
        var bits = new bool[bytes.Length * 8];
        for (int iByte = 0; iByte < bytes.Length; ++iByte)
        {
            byte b = bytes[iByte];
            for (int i = 0; i < 8; ++i)
            {
                bits[iByte * 8 + 7 - i] = (b & (1 << i)) != 0;
            }
        }
        AddRange(bits);
    }

    public static byte ConvertToByte(IEnumerable<bool> bits)
    {
        byte result = 0;
        for (int i = 0; i < 8; ++i)
        {
            if (bits.ElementAt(^(i + 1)))
            {
                result |= (byte)(1 << i);
            }
        }
        return result;
    }

    public static int ConvertBitsToInt(params bool[] ba)
    {
        int result = 0;
        for (int i = 0; i < ba.Length; i++)
        {
            if (ba[^(i + 1)])
            {
                result |= 1 << i;
            }
        }
        return result;
    }

    public BitArray Xor(BitArray ba)
    {
        if (Count != ba.Count)
        {
            throw new InvalidOperationException();
        }
        return new(this.Select((bit, i) => bit ^ ba[i]));
    }
    public BitArray LeftShift(int count)
    {
        var result = new BitArray(Count);

        for (int i = Count - 1; i >= count; --i)
        {
            result[i - count] = this[i];
        }
        for (int i = 0; i < count; ++i)
        {
            result[^(i + 1)] = this[count - 1 - i];
        }

        return result;
    }
    public byte[] GetBytes()
    {
        if (Count % 8 != 0)
        {
            throw new InvalidOperationException();
        }

        return Enumerable.Range(0, Count / 8)
            .Select(iByte => ConvertToByte(this.Skip(iByte * 8).Take(8)))
            .ToArray();
    }
    public BitArray GetRange(Range range)
    {
        return new(ToArray()[range]);
    }
    public BitArray ApplyTable(int[] table, int offset = -1)
    {
        return new(table.Select(i => this[i + offset]));
    }
    public int CountOnes()
    {
        return this.Count(b => b);
    }
}