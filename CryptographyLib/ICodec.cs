namespace CryptographyLib;

public interface ICodec<T1, T2>
{
    T2 Encrypt(T1 text);
    T1 Decrypt(T2 encrypted);
}