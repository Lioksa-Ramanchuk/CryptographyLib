using System.Text;

namespace Cryptography;

public abstract class StringSigner<T> : ByteSigner<T>, ISigner<string, T>
{
    public Encoding Encoding { get; set; } = Encoding.UTF8;

    public T Sign(string text)
    {
        return Sign(Encoding.GetBytes(text));
    }

    public bool VerifySignature(string text, T signature)
    {
        return VerifySignature(Encoding.UTF8.GetBytes(text), signature);
    }
}