namespace Cryptography;

public abstract class AsymmetricCipher<T> : Cipher<byte[], T[]>
{
    protected override void ProcessFile(string pathFrom, string pathTo, Mode mode)
    {
        using var reader = new BinaryReader(new FileStream(pathFrom, FileMode.Open));
        using var writer = new BinaryWriter(new FileStream(pathTo, FileMode.Create));

        switch (mode)
        {
            case Mode.Encryption:
                EncryptingFile(reader, writer, Encrypt);
                break;
            case Mode.Decryption:
                DecryptingFile(reader, writer, Decrypt);
                break;
            default:
                throw new ArgumentException("Invalid cipher mode.", nameof(mode));
        }
    }

    protected abstract void EncryptingFile(BinaryReader reader, BinaryWriter writer, Func<byte[], T[]> encryptBuf, int bufSize = 1024);

    protected abstract void DecryptingFile(BinaryReader reader, BinaryWriter writer, Func<T[], byte[]> decryptBigIntegers);
}