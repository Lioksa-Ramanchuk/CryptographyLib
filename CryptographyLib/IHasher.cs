namespace CryptographyLib;

public interface IHasher<T1, T2>
{
    T2 Hash(T1 text);
}