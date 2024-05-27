namespace CryptographyLib;

public interface IFileHasher
{
    void HashFile(string pathText, string pathHashed);
}