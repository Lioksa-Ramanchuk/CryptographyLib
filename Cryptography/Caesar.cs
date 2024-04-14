namespace Cryptography;
using System.Text;

public class Caesar(char[] alphabet, int offset) : StringCipher
{
    public char[] Alphabet { get; set; } = alphabet;
    public int Offset { get; set; } = offset;

    public override string Encrypt(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        StringBuilder encrypted = new();

        foreach (char letter in text)
        {
            int index = Array.IndexOf(Alphabet, char.ToUpper(letter));
            if (index == -1)
            {
                encrypted.Append(letter);
            }
            else
            {
                int encryptedIndex = (((index + Offset) % Alphabet.Length) + Alphabet.Length) % Alphabet.Length;
                char encryptedUppercaseLetter = Alphabet[encryptedIndex];
                encrypted.Append(char.IsUpper(letter) ? encryptedUppercaseLetter : char.ToLower(encryptedUppercaseLetter));
            }
        }

        return encrypted.ToString();
    }

    public override string Decrypt(string encrypted)
    {
        var codec = new Caesar(Alphabet, -Offset);
        return codec.Encrypt(encrypted);
    }
}
