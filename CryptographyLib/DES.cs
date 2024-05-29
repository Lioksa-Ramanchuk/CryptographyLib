namespace CryptographyLib;
using Utils;

public class DES : ByteCipher
{
    private const int _kBlockSize = 8;
    private const int _kRoundsNumber = 16;

    private static readonly int[] IP =
    [
        58,  50,  42,  34,  26,  18,  10,  2,
        60,  52,  44,  36,  28,  20,  12,  4,
        62,  54,  46,  38,  30,  22,  14,  6,
        64,  56,  48,  40,  32,  24,  16,  8,
        57,  49,  41,  33,  25,  17,  9,   1,
        59,  51,  43,  35,  27,  19,  11,  3,
        61,  53,  45,  37,  29,  21,  13,  5,
        63,  55,  47,  39,  31,  23,  15,  7

    ];
    private static readonly int[] PC1 =
    [
        57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,

        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4
    ];
    private static readonly int[] Shifts =
    [
        1,  1,  2,  2,  2,  2,  2,  2,
        1,  2,  2,  2,  2,  2,  2,  1
    ];
    private static readonly int[] PC2 =
    [
        14, 17, 11, 24, 1,  5,
        3,  28, 15, 6,  21, 10,
        23, 19, 12, 4,  26, 8,
        16, 7,  27, 20, 13, 2,

        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ];
    private static readonly int[] E =
    [
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ];
    private static readonly int[,] S1 = new int[,]
    {
        { 14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7 },
        { 0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8 },
        { 4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0 },
        { 15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13 }
    };
    private static readonly int[,] S2 = new int[,]
    {
        { 15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10 },
        { 3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5 },
        { 0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15 },
        { 13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9 }
    };
    private static readonly int[,] S3 = new int[,]
    {
        { 10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8 },
        { 13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1 },
        { 13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7 },
        { 1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12 }
    };
    private static readonly int[,] S4 = new int[,]
    {
        { 7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15 },
        { 13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9 },
        { 10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4 },
        { 3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14 }
    };
    private static readonly int[,] S5 = new int[,]
    {
        { 2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9 },
        { 14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6 },
        { 4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14 },
        { 11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3 }
    };
    private static readonly int[,] S6 = new int[,]
    {
        { 12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11 },
        { 10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8 },
        { 9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6 },
        { 4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13 }
    };
    private static readonly int[,] S7 = new int[,]
    {
        { 4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1 },
        { 13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6 },
        { 1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2 },
        { 6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12 }
    };
    private static readonly int[,] S8 = new int[,]
    {
        { 13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7 },
        { 1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2 },
        { 7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8 },
        { 2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11 }
    };
    private static readonly int[][,] S_boxes = [S1, S2, S3, S4, S5, S6, S7, S8];
    private static readonly int[] P =
    [
        16, 7,  20, 21, 29, 12, 28, 17,
        1,  15, 23, 26, 5,  18, 31, 10,
        2,  8,  24, 14, 32, 27, 3,  9,
        19, 13, 30, 6,  22, 11, 4,  25
    ];
    private static readonly int[] IP2 =
    [
        40,  8,   48,  16,  56,  24,  64,  32,
        39,  7,   47,  15,  55,  23,  63,  31,
        38,  6,   46,  14,  54,  22,  62,  30,
        37,  5,   45,  13,  53,  21,  61,  29,
        36,  4,   44,  12,  52,  20,  60,  28,
        35,  3,   43,  11,  51,  19,  59,  27,
        34,  2,   42,  10,  50,  18,  58,  26,
        33,  1,   41,   9,  49,  17,  57,  25
    ];

    private byte[] _key = null!;
    private Mode _mode = Mode.Encryption;

    public DES(byte[] key)
    {
        Key = key;
    }

    public byte[] Key
    {
        get => _key;
        set
        {
            ValidateKey(value);
            _key = value;
        }
    }

    public override byte[] Encrypt(byte[] text)
    {
        var blocks = SplitIntoBlocks(text);

        var key = SplitIntoBlocks(Key).Single();
        key = key.ApplyTable(PC1);
        var subkeys = new BitArray[_kRoundsNumber];
        for (int iRound = 0; iRound < _kRoundsNumber; ++iRound)
        {
            key = ShiftKey(key, Shifts[iRound]);
            subkeys[iRound] = key.ApplyTable(PC2);
        }
        if (_mode == Mode.Decryption)
        {
            Array.Reverse(subkeys);
        }

        for (int iBlock = 0; iBlock < blocks.Length; ++iBlock)
        {
            var block = blocks[iBlock].ApplyTable(IP);

            var left = block.GetRange(..(block.Count / 2));
            var right = block.GetRange((block.Count / 2)..);

            for (int iRound = 0; iRound < _kRoundsNumber; ++iRound)
            {
                (left, right) = (right, left.Xor(F(right, subkeys[iRound])));
            }

            blocks[iBlock] = new BitArray(right.Concat(left)).ApplyTable(IP2);
        }

        return blocks.SelectMany(block => block.GetBytes()).ToArray();
    }
    public override byte[] Decrypt(byte[] encrypted)
    {
        var codec = new DES(_key)
        {
            _mode = Mode.Decryption,
        };
        return codec.Encrypt(encrypted);
    }

    protected override void ProcessingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], byte[]> processBuf, int bufSize)
    {
        bufSize = _kBlockSize * 128;
        var buf = new byte[bufSize];
        int bytesRead;
        while ((bytesRead = reader.Read(buf, 0, bufSize)) > 0)
        {
            writer.Write(processBuf(buf[..bytesRead]));
        }
    }

    public static double CalculateAvalanche(byte[] encrypted1, byte[] encrypted2)
    {
        var xored = new BitArray(encrypted1).Xor(new BitArray(encrypted2));
        return 100.0 * xored.CountOnes() / xored.Count;
    }
    private static void ValidateKey(byte[] key)
    {
        if (key.Length != _kBlockSize)
        {
            throw new ArgumentException("Invalid key.", nameof(key));
        }
    }
    private static BitArray[] SplitIntoBlocks(byte[] bytes)
    {
        int nBlocks = (bytes.Length + _kBlockSize - 1) / _kBlockSize;
        var blocks = new BitArray[nBlocks];
        for (int iBlock = 0; iBlock < nBlocks; ++iBlock)
        {
            blocks[iBlock] = new(bytes.Skip(iBlock * _kBlockSize).TakeOrDefault(_kBlockSize).ToArray());
        }
        return blocks;
    }
    private static BitArray ShiftKey(BitArray key, int shift)
    {
        var left = key.GetRange(..(key.Count / 2)).LeftShift(shift);
        var right = key.GetRange((key.Count / 2)..).LeftShift(shift);
        return new(left.Concat(right));
    }
    private static BitArray F(BitArray right, BitArray key)
    {
        right = right.ApplyTable(E).Xor(key);

        var result = new BitArray(_kBlockSize * 8 / 2);

        var kGroupsNumber = S_boxes.Length;
        var kGroupBitsSize = E.Length / kGroupsNumber;
        var kGroupWrittenBitsSize = P.Length / kGroupsNumber;

        for (int iGroup = 0; iGroup < kGroupsNumber; ++iGroup)
        {
            var groupStart = iGroup * kGroupBitsSize;
            var groupEnd = groupStart + kGroupBitsSize;
            var row = BitArray.ConvertBitsToInt(right[groupStart], right[groupEnd - 1]);
            var col = BitArray.ConvertBitsToInt(right.ToArray()[(groupStart + 1)..(groupEnd - 1)]);

            var value = S_boxes[iGroup][row, col];
            for (int i = 0; i < kGroupWrittenBitsSize; ++i)
            {
                result[(iGroup + 1) * kGroupWrittenBitsSize - 1 - i] = (value & (1 << i)) != 0;
            }
        }

        return result.ApplyTable(P);
    }
}