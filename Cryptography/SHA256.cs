namespace Cryptography;

public class SHA256 : ByteHasher
{
    public override byte[] Hash(byte[] text)
    {
        return System.Security.Cryptography.SHA256.HashData(text);
    }
}