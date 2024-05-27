namespace CryptographyLib;

public static class Alphabet
{
    public static char[] Base64 { get; } =
    [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/',
    ];

    public static char[] Belarusian { get; } =
    [
        'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж',
        'З', 'І', 'Й', 'К', 'Л', 'М', 'Н', 'О',
        'П', 'Р', 'С', 'Т', 'У', 'Ў', 'Ф', 'Х',
        'Ц', 'Ч', 'Ш', 'Ы', 'Ь', 'Э', 'Ю', 'Я',
    ];

    public static char[] Binary { get; } =
    [
        '0', '1',
    ];

    public static char[] English { get; } =
    [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z',
    ];

    public static char[] German { get; } =
    [
        'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'Ä', 'Ö', 'Ü', 'ß',
    ];
    public static char[] GermanFull { get; } =
    [
        'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'Ä', 'Ö', 'Ü', 'ẞ',
        'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x',
        'y', 'z', 'ä', 'ö', 'ü', 'ß',
    ];
}
