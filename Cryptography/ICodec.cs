namespace Cryptography;

public interface ICodec<T>
{
    T Encrypt(T text);
    T Decrypt(T encrypted);
}