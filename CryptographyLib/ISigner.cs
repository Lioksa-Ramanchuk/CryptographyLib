namespace CryptographyLib;

public interface ISigner<T1, T2>
{
    T2 Sign(T1 data);
    bool VerifySignature(T1 data, T2 signature);
}