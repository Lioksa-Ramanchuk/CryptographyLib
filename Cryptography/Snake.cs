namespace Cryptography;
using System.Text;

public class Snake(int columns) : StringCipher
{
    private Direction _writeDirection = Direction.Straight;

    private enum Direction
    {
        Straight = 1,
        Snake = -1,
    }

    public int NColumns { get; private set; } = columns;

    public override string Encrypt(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        StringBuilder encrypted = new();
        int nRows = (int)Math.Ceiling((decimal)text.Length / NColumns);
        var table = new char?[nRows, NColumns];

        void StraightTraversal(Action<int, int> action)
        {
            for (int iRow = 0; iRow < nRows; ++iRow)
            {
                for (int iCol = 0; iCol < NColumns; ++iCol)
                {
                    action(iRow, iCol);
                }
            }
        }

        void SnakeTraversal(Action<int, int> action)
        {
            for (int layer = 0; layer < nRows + NColumns - 1; ++layer)
            {
                int start_iCol = Math.Max(0, layer - nRows + 1);
                int count = Math.Min(Math.Min(layer + 1, nRows), NColumns - start_iCol);

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
                        iRow = Math.Max(0, layer - NColumns + 1) + i;
                        iCol = Math.Min(NColumns - 1, layer) - i;
                    }

                    action(iRow, iCol);
                }
            }
        }

        if (_writeDirection == Direction.Straight)
        {
            StraightTraversal((int iRow, int iCol) =>
            {
                int i = (iRow * NColumns) + iCol;
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
        var codec = new Snake(NColumns)
        {
            _writeDirection = Direction.Snake,
        };
        return codec.Encrypt(encrypted);
    }
}