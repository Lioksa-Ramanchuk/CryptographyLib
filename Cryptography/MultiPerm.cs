namespace Cryptography;
using System.Text;

public class MultiPerm : StringCipher
{
    private string _key1 = null!;
    private string _key2 = null!;
    private int[] _key1Indices = null!;
    private int[] _key2Indices = null!;
    private Mode _mode = Mode.Encryption;

    public MultiPerm(string key1, string key2, char[] alphabet)
    {
        Key1 = key1;
        Key2 = key2;
        Alphabet = alphabet;
    }

    public string Key1
    {
        get => _key1;
        set
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("Invalid key", nameof(Key1));
            }
            _key1Indices = GetLettersOrder(value);
            _key1 = value;
        }
    }
    public string Key2
    {
        get => _key2;
        set
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("Invalid key", nameof(Key2));
            }
            _key2Indices = GetLettersOrder(value);
            _key2 = value;
        }
    }
    public char[] Alphabet { get; set; }

    public override string Encrypt(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        if (text.Length > _key1Indices.Length * _key2Indices.Length)
        {
            throw new ArgumentException("Text is too long for the keys", nameof(text));
        }

        StringBuilder encrypted = new();
        var nRows = _key2Indices.Length;
        var nColumns = _key1Indices.Length;

        var table = new char?[nRows, nColumns];

        void StraightTraversal(Action<int, int> action)
        {
            for (int iRow = 0; iRow < nRows; ++iRow)
            {
                for (int iCol = 0; iCol < nColumns; ++iCol)
                {
                    action(iRow, iCol);
                }
            }
        }

        if (_mode == Mode.Encryption)
        {
            StraightTraversal((int iRow, int iCol) =>
            {
                int i = iRow * nColumns + iCol;
                table[_key2Indices[iRow], _key1Indices[iCol]] = i < text.Length ? text[i] : null;
            });
            StraightTraversal((int iRow, int iCol) =>
            {
                encrypted.Append(table[iRow, iCol] ?? '\0');
            });
        }
        else
        {
            StraightTraversal((int iRow, int iCol) =>
            {
                int i = _key2Indices[iRow] * nColumns + _key1Indices[iCol];
                if (i < text.Length && text[i] != '\0')
                {
                    encrypted.Append(text[i]);
                }
            });
        }

        return encrypted.ToString();
    }
    public override string Decrypt(string encrypted)
    {
        var codec = new MultiPerm(_key1, _key2, Alphabet)
        {
            _mode = Mode.Decryption,
        };
        return codec.Encrypt(encrypted);
    }

    protected override void ProcessingFile(StreamReader reader, StreamWriter writer, Func<string, string> processLine)
    {
        var blockLength = _key1Indices.Length * _key2Indices.Length;

        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrEmpty(line))
            {
                writer.WriteLine();
                continue;
            }

            int nBlocks = (line.Length + blockLength - 1) / blockLength;
            for (int i = 0; i < nBlocks; ++i)
            {
                int start = i * blockLength;
                int length = Math.Min(blockLength, line.Length - start);
                writer.WriteLine(processLine(line.Substring(start, length)));
            }
        }
    }

    private int[] GetLettersOrder(string key)
    {
        var germanAlphabet = Alphabet.ToArray();
        return key
            .Select((letter, i) => new { code = Array.IndexOf(germanAlphabet, char.ToUpper(letter)), initialIndex = i })
            .OrderBy(x => x.code)
            .Select((x, i) => new { x.initialIndex, sortedIndex = i })
            .OrderBy(x => x.initialIndex)
            .Select(x => x.sortedIndex)
            .ToArray();
    }
}