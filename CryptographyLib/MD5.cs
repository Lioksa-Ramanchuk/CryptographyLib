namespace CryptographyLib;

public class MD5 : ByteHasher
{
    public override byte[] Hash(byte[] text)
    {
        return System.Security.Cryptography.MD5.HashData(text);
    }
}