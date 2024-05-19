namespace Cryptography;

public abstract class Signer<T1, T2> : ISigner<T1, T2>
{
    public abstract T2 Sign(T1 data);
    public abstract bool VerifySignature(T1 data, T2 signature);
}