using System.Text;

namespace CryptographyLib.Utils;

public static class XEncoding
{
    public static void RegisterInstanceEncodings()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public static Encoding Windows1251 => Encoding.GetEncoding(1251);
}