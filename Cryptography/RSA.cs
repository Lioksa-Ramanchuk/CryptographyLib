namespace Cryptography;

using SysCryptography = System.Security.Cryptography;

public class RSA : ByteCipher
{
    public RSA(int keySize = 2048)
    {
        KeySize = keySize;
        using var rsa = new SysCryptography.RSACryptoServiceProvider(keySize);
        PrivateKeyParameters = rsa.ExportParameters(true);
        PublicKeyParameters = rsa.ExportParameters(false);
    }

    public int KeySize { get; }
    public SysCryptography.RSAParameters PublicKeyParameters { get; }
    public SysCryptography.RSAParameters PrivateKeyParameters { get; }

    public override byte[] Encrypt(byte[] text)
    {
        using var rsa = new SysCryptography.RSACryptoServiceProvider();
        rsa.ImportParameters(PublicKeyParameters);
        return rsa.Encrypt(text, false);
    }

    public override byte[] Decrypt(byte[] encrypted)
    {
        using var rsa = new SysCryptography.RSACryptoServiceProvider();
        rsa.ImportParameters(PrivateKeyParameters);
        return rsa.Decrypt(encrypted, false);
    }

    protected override void ProcessFile(string pathFrom, string pathTo, Mode mode)
    {
        using var reader = new BinaryReader(new FileStream(pathFrom, FileMode.Open));
        using var writer = new BinaryWriter(new FileStream(pathTo, FileMode.Create));

        switch (mode)
        {
            case Mode.Encryption:
                ProcessingFile(reader, writer, Encrypt, ((KeySize - 384) / 8) + 37);
                break;
            case Mode.Decryption:
                ProcessingFile(reader, writer, Decrypt, KeySize / 8);
                break;
            default:
                throw new ArgumentException("Invalid cipher mode.", nameof(mode));
        };
    }
}