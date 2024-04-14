namespace Cryptography;
using System.Text;

public class Base64(Encoding encoding) : StringCipher
{
    public Encoding Encoding { get; set; } = encoding;

    public override string Encrypt(string text)
    {
        return Convert.ToBase64String(Encoding.GetBytes(text));
    }
    public override string Decrypt(string encrypted)
    {
        return Encoding.GetString(Convert.FromBase64String(encrypted));
    }
}