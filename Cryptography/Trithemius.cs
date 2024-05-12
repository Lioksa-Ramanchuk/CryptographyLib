namespace Cryptography;
using System.Text;

public class Trithemius : StringCipher
{
    private Mode _mode = Mode.Encryption;

    public Trithemius(char[] alphabet, int columns, string? key = null)
    {
        if (string.IsNullOrEmpty(key))
        {
            Alphabet = alphabet;
        }
        else
        {
            var keyAlphabet = key.ToUpper().ToCharArray().Distinct();
            var tableAlphabet = keyAlphabet.Concat(alphabet.Except(keyAlphabet));
            Alphabet = tableAlphabet.ToArray();
        }

        TableSize = ((Alphabet.Length + columns - 1) / columns, columns);
    }

    public char[] Alphabet { get; private set; }
    public (int rows, int columns) TableSize { get; private set; }

    public override string Encrypt(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        StringBuilder encrypted = new();

        int GetEncryptedIndex(int index)
        {
            var encryptedIndex = index;

            if (_mode == Mode.Encryption)
            {
                encryptedIndex += TableSize.columns;
                if (encryptedIndex >= Alphabet.Length)
                {
                    encryptedIndex %= TableSize.columns;
                }
            }
            else
            {
                encryptedIndex -= TableSize.columns;
                if (encryptedIndex < 0)
                {
                    encryptedIndex += TableSize.rows * TableSize.columns;
                    if (encryptedIndex > Alphabet.Length)
                    {
                        encryptedIndex -= TableSize.columns;
                    }
                }
            }

            return encryptedIndex;
        }

        foreach (char letter in text)
        {
            int index = Array.IndexOf(Alphabet, char.ToUpper(letter));
            if (index == -1)
            {
                encrypted.Append(letter);
            }
            else
            {
                char encryptedUppercaseLetter = Alphabet[GetEncryptedIndex(index)];
                encrypted.Append(char.IsUpper(letter) ? encryptedUppercaseLetter : char.ToLower(encryptedUppercaseLetter));
            }
        }

        return encrypted.ToString();
    }
    public override string Decrypt(string encrypted)
    {
        var codec = new Trithemius(Alphabet, TableSize.columns)
        {
            _mode = Mode.Decryption,
        };
        return codec.Encrypt(encrypted);
    }
}