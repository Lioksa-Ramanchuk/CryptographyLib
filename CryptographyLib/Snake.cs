namespace CryptographyLib;
using System.Text;

public class Snake(int nColumns) : StringCipher
{
    private Mode _mode = Mode.Encryption;

    public override string Encrypt(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        StringBuilder encrypted = new();
        int nRows = (text.Length + nColumns - 1) / nColumns;
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

        void SnakeTraversal(Action<int, int> action)
        {
            for (int layer = 0; layer < nRows + nColumns - 1; ++layer)
            {
                int start_iCol = Math.Max(0, layer - nRows + 1);
                int count = Math.Min(Math.Min(layer + 1, nRows), nColumns - start_iCol);

                for (int i = 0; i < count; ++i)
                {
                    int iRow, iCol;
                    if (layer % 2 == 0)
                    {
                        iRow = Math.Min(nRows - 1, layer) - i;
                        iCol = start_iCol + i;
                    }
                    else
                    {
                        iRow = Math.Max(0, layer - nColumns + 1) + i;
                        iCol = Math.Min(nColumns - 1, layer) - i;
                    }

                    action(iRow, iCol);
                }
            }
        }

        if (_mode == Mode.Encryption)
        {
            StraightTraversal((int iRow, int iCol) =>
            {
                int i = iRow * nColumns + iCol;
                table[iRow, iCol] = i < text.Length ? text[i] : null;
            });
            SnakeTraversal((int iRow, int iCol) =>
            {
                encrypted.Append(table[iRow, iCol] ?? '\0');
            });
        }
        else
        {
            int iToWrite = 0;
            SnakeTraversal((int iRow, int iCol) =>
            {
                table[iRow, iCol] = iToWrite < text.Length && text[iToWrite] != '\0' ? text[iToWrite] : null;
                ++iToWrite;
            });
            StraightTraversal((int iRow, int iCol) =>
            {
                if (table[iRow, iCol] != null)
                {
                    encrypted.Append(table[iRow, iCol]);
                }
            });
        }

        return encrypted.ToString();
    }
    public override string Decrypt(string encrypted)
    {
        var codec = new Snake(nColumns)
        {
            _mode = Mode.Decryption,
        };
        return codec.Encrypt(encrypted);
    }
}