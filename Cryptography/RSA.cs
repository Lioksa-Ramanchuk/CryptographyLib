using System.Numerics;
using System.Security.Cryptography;

namespace Cryptography;

public class RSA : ByteCipher
{
    private RSAParameters privateKeyParameters;
    private RSAParameters publicKeyParameters;

    public RSA(int keySize = 2048)
    {
        using var rsa = new RSACryptoServiceProvider(keySize);
        privateKeyParameters = rsa.ExportParameters(true);
        publicKeyParameters = rsa.ExportParameters(false);
    }

    public override byte[] Encrypt(byte[] text)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(publicKeyParameters);
        return rsa.Encrypt(text, false);
    }

    public override byte[] Decrypt(byte[] encrypted)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(privateKeyParameters);
        return rsa.Decrypt(encrypted, false);
    }
}