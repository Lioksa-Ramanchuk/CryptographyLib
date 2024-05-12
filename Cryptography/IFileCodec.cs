namespace Cryptography;

public interface IFileCodec
{
    void EncryptFile(string pathText, string pathEncrypted);
    void DecryptFile(string pathEncrypted, string pathText);
}