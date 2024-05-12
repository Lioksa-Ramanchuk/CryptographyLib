namespace Cryptography;
using System.Text;

public class Caesar(char[] alphabet, int offset) : StringCipher
{
    private Mode _mode = Mode.Encryption;

    public override string Encrypt(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var adjustedOffset = _mode == Mode.Encryption ? offset : -offset;
        if (adjustedOffset < 0)
        {
            adjustedOffset = (adjustedOffset % alphabet.Length + alphabet.Length) % alphabet.Length;
        }

        StringBuilder encrypted = new();

        foreach (char letter in text)
        {
            int index = Array.IndexOf(alphabet, char.ToUpper(letter));
            if (index == -1)
            {
                encrypted.Append(letter);
            }
            else
            {
                int encryptedIndex = (index + adjustedOffset) % alphabet.Length;
                char encryptedUppercaseLetter = alphabet[encryptedIndex];
                encrypted.Append(char.IsUpper(letter) ? encryptedUppercaseLetter : char.ToLower(encryptedUppercaseLetter));
            }
        }

        return encrypted.ToString();
    }

    public override string Decrypt(string encrypted)
    {
        var codec = new Caesar(alphabet, offset)
        {
            _mode = Mode.Decryption
        };
        return codec.Encrypt(encrypted);
    }
}