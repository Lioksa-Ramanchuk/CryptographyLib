namespace CryptographyLib.Utils;

public static partial class Extensions
{
    public static IEnumerable<T?> TakeOrDefault<T>(this IEnumerable<T> items, int count)
    {
        var i = 0;
        foreach (var item in items)
        {
            yield return item;
            if (++i == count)
            {
                yield break;
            }
        }
        while (i++ < count)
        {
            yield return default;
        }
    }
}