namespace Cryptography;
using System.Text;

public class TextAnalyzer
{
    public const double kDefaultEpsilon = 0.0001;
    public static readonly Encoding kDefaultEncoding = Encoding.UTF8;

    public string? Text { get; private set; }
    public string? TextPath { get; private set; }
    public Encoding Encoding { get; private set; } = kDefaultEncoding;
    public Dictionary<char, long>? SymbolsOccurences { get; private set; }
    public Dictionary<char, double>? SymbolsProbabilities { get; private set; }
    public char[]? Alphabet { get; private set; }
    public long? SymbolsCount { get; private set; }
    public double? ShannonEntropy { get; private set; }
    public double? HartleyEntropy { get; private set; }
    public double? Redundancy { get; private set; }
    public double? InformationQuantity { get; private set; }
    public double Epsilon { get; set; } = kDefaultEpsilon;

    public TextAnalyzer Clear()
    {
        Text = null;
        TextPath = null;
        Encoding = kDefaultEncoding;
        Alphabet = null;
        SymbolsOccurences = null;
        SymbolsProbabilities = null;
        SymbolsCount = null;
        ShannonEntropy = null;
        HartleyEntropy = null;
        Redundancy = null;
        InformationQuantity = null;
        Epsilon = kDefaultEpsilon;
        return this;
    }

    public TextAnalyzer UseText(string text)
    {
        (Text, TextPath) = (text, null);
        return this;
    }
    public TextAnalyzer UseFile(string textPath)
    {
        (Text, TextPath) = (null, textPath);
        return this;
    }

    public TextAnalyzer WithEncoding(Encoding? encoding)
    {
        Encoding = encoding ?? kDefaultEncoding;
        return this;
    }
    public TextAnalyzer WithAlphabet(char[]? alphabet)
    {
        Alphabet = alphabet;
        return this;
    }
    public TextAnalyzer WithEpsilon(double? epsilon)
    {
        Epsilon = epsilon ?? kDefaultEpsilon;
        return this;
    }

    public TextAnalyzer CalcSymbolsOccurences(bool useAlphabet = true, bool useUppercase = true, bool useBinary = false)
    {
        if (Text is null && TextPath is null)
        {
            throw new InvalidOperationException("Text is not set");
        }

        SymbolsOccurences = new();

        if (Alphabet is null)
        {
            useAlphabet = false;
        }

        if (useAlphabet)
        {
            foreach (var c in Alphabet!)
            {
                SymbolsOccurences.Add(c, 0);
            }
        }

        void ProcessSymbol(char c)
        {
            if (useUppercase)
            {
                c = char.ToUpper(c);
            }

            if (!useAlphabet && !SymbolsOccurences.ContainsKey(c))
            {
                SymbolsOccurences.Add(c, 0);
            }

            if (!useAlphabet || Alphabet!.Contains(c))
            {
                ++SymbolsOccurences![c];
            }
        }

        if (useBinary)
        {
            void ProcessByte(byte b)
            {
                for (int iBit = 0; iBit < 8; ++iBit)
                {
                    ProcessSymbol((b & (1 << iBit)) == 0 ? '0' : '1');
                }
            }

            if (Text is not null)
            {
                byte[] bytes = Encoding.GetBytes(Text!);
                foreach (var b in bytes)
                {
                    ProcessByte(b);
                }
            }
            else if (TextPath is not null)
            {
                using var fs = File.OpenRead(TextPath);
                byte[] bytes = new byte[1024];
                int bytesRead;
                while ((bytesRead = fs.Read(bytes, 0, bytes.Length)) > 0)
                {
                    for (int iByte = 0; iByte < bytesRead; ++iByte)
                    {
                        ProcessByte(bytes[iByte]);
                    }
                }
            }
        }
        else
        {
            if (Text is not null)
            {
                foreach (var c in Text)
                {
                    ProcessSymbol(c);
                }
            }
            else if (TextPath is not null)
            {
                using var sr = new StreamReader(TextPath);
                for (var c = (char)sr.Read(); !sr.EndOfStream; c = (char)sr.Read())
                {
                    ProcessSymbol(c);
                }
            }
        }

        return this;
    }
    public TextAnalyzer CalcSymbolsCount()
    {
        if (SymbolsOccurences is null)
        {
            CalcSymbolsOccurences();
        }

        SymbolsCount = SymbolsOccurences!.Values.Sum();
        return this;
    }
    public TextAnalyzer CalcSymbolsProbabilities()
    {
        if (SymbolsOccurences is null)
        {
            CalcSymbolsOccurences();
        }

        if (SymbolsCount is null)
        {
            CalcSymbolsCount();
        }

        SymbolsProbabilities = new();
        foreach (var (c, count) in SymbolsOccurences!)
        {
            SymbolsProbabilities.Add(c, (double)((double)count / SymbolsCount!));
        }

        return this;
    }
    public TextAnalyzer CalcShannonEntropy()
    {
        if (SymbolsProbabilities is null)
        {
            CalcSymbolsProbabilities();
        }

        double entropy = 0.0;
        foreach (var (c, q) in SymbolsProbabilities!)
        {
            if (q > Epsilon)
            {
                entropy -= q * Math.Log2(q);
            }
        }

        return this;
    }
    public TextAnalyzer CalcHartleyEntropy()
    {
        int n;
        if (Alphabet is not null)
        {
            n = Alphabet.Length;
        }
        else
        {
            if (SymbolsOccurences is null)
            {
                CalcSymbolsOccurences();
            }

            n = SymbolsOccurences!.Count;
        }

        HartleyEntropy = Math.Log2(n);
        return this;
    }
    public TextAnalyzer CalcRedundancy()
    {
        if (HartleyEntropy is null)
        {
            CalcHartleyEntropy();
        }

        if (ShannonEntropy is null)
        {
            CalcShannonEntropy();
        }

        Redundancy = (HartleyEntropy! - ShannonEntropy!) / HartleyEntropy!;
        return this;
    }
    public TextAnalyzer CalcInformationQuantity(double p = 0, bool useBinary = false)
    {
        if (ShannonEntropy is null)
        {
            CalcShannonEntropy();
        }

        if (SymbolsCount is null)
        {
            CalcSymbolsCount();
        }

        double q = 1 - p;
        double informationLoss;
        if (p < Epsilon)
        {
            informationLoss = 0;
        }
        else if (q < Epsilon)
        {
            informationLoss = useBinary ? 0 : 1;
        }
        else
        {
            informationLoss = -p * Math.Log2(p) - q * Math.Log2(q);
        }

        InformationQuantity = (double)(ShannonEntropy! * (1 - informationLoss) * SymbolsCount!);
        return this;
    }
}
