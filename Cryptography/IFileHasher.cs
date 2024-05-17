namespace Cryptography;

public interface IFileHasher
{
    void HashFile(string pathText, string pathHashed);
}