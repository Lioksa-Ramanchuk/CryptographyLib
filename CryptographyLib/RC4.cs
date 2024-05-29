namespace CryptographyLib;

public class RC4 : StreamCipher
{
    private readonly byte[] _key;
    private byte[] _s = null!;
    private int _i = 0;
    private int _j = 0;

    public RC4(byte[] key)
    {
        _key = key;
        Reset();
    }

    public override byte[] Encrypt(byte[] text)
    {
        var encrypted = new List<byte>(text.Length);
        foreach (byte b in text)
        {
            _i = (_i + 1) % 256;
            _j = (_j + _s[_i]) % 256;
            (_s[_i], _s[_j]) = (_s[_j], _s[_i]);
            encrypted.Add((byte)(b ^ _s[(_s[_i] + _s[_j]) % 256]));
        }
        return [.. encrypted];
    }

    public override byte[] Decrypt(byte[] encrypted)
    {
        return Encrypt(encrypted);
    }

    public void Reset()
    {
        _s = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        for (int i = 0, j = 0; i < 256; ++i)
        {
            j = (j + _s[i] + _key[i % _key.Length]) % 256;
            (_s[i], _s[j]) = (_s[j], _s[i]);
        }
        _i = _j = 0;
    }
}