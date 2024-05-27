namespace CryptographyLib;
using System.Text;

public class Base64(Encoding encoding) : StringCipher
{
    public override string Encrypt(string text)
    {
        return Convert.ToBase64String(encoding.GetBytes(text));
    }
    public override string Decrypt(string encrypted)
    {
        return encoding.GetString(Convert.FromBase64String(encrypted));
    }
}