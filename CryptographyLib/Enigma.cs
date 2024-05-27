namespace CryptographyLib;
using System.Text;

public class Enigma : StringCipher
{
    public static readonly string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static readonly int AlphabetLength = Alphabet.Length;
    private EnigmaRotor[] _rotors = null!;

    public Enigma(EnigmaRotor[] rotors, EnigmaReflector reflector, EnigmaPlugboard plugboard)
    {
        Rotors = rotors;
        Reflector = reflector;
        Plugboard = plugboard;
    }

    public EnigmaRotor[] Rotors
    {
        get => _rotors;
        set
        {
            _rotors = value;
            for (var i = _rotors.Length - 2; i >= 0; --i)
            {
                if (_rotors[i].Step is null)
                {
                    var currentRotor = _rotors[i];
                    _rotors[i + 1].OnNotch += currentRotor.Rotate;
                }
            }
        }
    }
    public EnigmaReflector Reflector { get; set; }
    public EnigmaPlugboard Plugboard { get; set; }

    public override string Encrypt(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            sb.Append(Encrypt(c));
        }

        return sb.ToString();
    }
    public override string Decrypt(string encrypted)
    {
        return Encrypt(encrypted);
    }
    private char Encrypt(char letter)
    {
        var letterUppercase = char.ToUpper(letter);
        if (!Alphabet.Contains(letterUppercase))
        {
            return letter;
        }

        letterUppercase = Plugboard.SwapIfPlugged(letterUppercase);
        for (int i = Rotors.Length - 1; i >= 0; --i)
        {
            Rotors[i].Rotate();
            letterUppercase = Rotors[i].Forward(letterUppercase);
        }

        letterUppercase = Reflector.Reflect(letterUppercase);
        for (int i = 0; i < Rotors.Length; ++i)
        {
            letterUppercase = Rotors[i].Backward(letterUppercase);
        }

        letterUppercase = Plugboard.SwapIfPlugged(letterUppercase);

        return char.IsUpper(letter) ? letterUppercase : char.ToLower(letterUppercase);
    }

    public class EnigmaPlugboard
    {
        private Dictionary<char, char> _mapping = null!;

        public EnigmaPlugboard(Dictionary<char, char> mapping)
        {
            Mapping = mapping;
        }

        public Dictionary<char, char> Mapping
        {
            get => _mapping;
            set
            {
                AdjustPlugboardMapping(value);
                ValidatePlugboardMapping(value);
                _mapping = value;
            }
        }

        public static void AdjustPlugboardMapping(Dictionary<char, char> mapping)
        {
            var pairs = mapping.ToList();
            foreach (var pair in pairs)
            {
                if (pair.Key == pair.Value)
                {
                    mapping.Remove(pair.Key);
                }
                else if (!mapping.ContainsKey(pair.Value))
                {
                    mapping.Add(pair.Value, pair.Key);
                }
            }
        }
        public static void ValidatePlugboardMapping(Dictionary<char, char> mapping)
        {
            var keys = new HashSet<char>(mapping.Keys);
            var values = new HashSet<char>(mapping.Values);

            if (!keys.SetEquals(values) || keys.Any(k => k != mapping[mapping[k]]))
            {
                throw new ArgumentException("Invalid mapping.", nameof(mapping));
            }
        }

        public char SwapIfPlugged(char c)
        {
            return Mapping.TryGetValue(c, out char value) ? value : c;
        }
    }
    public class EnigmaRotor
    {
        private string _mapping = null!;
        private int _position;

        public EnigmaRotor(string mapping, char[] notches, char position = 'A', int? step = null)
        {
            Mapping = mapping;
            Position = position - 'A';
            Step = step;
            Notches = notches.Select(c => c - 'A').ToArray();
        }
        public EnigmaRotor(EnigmaRotor rotor)
        {
            _mapping = rotor._mapping;
            _position = rotor._position;
            Step = rotor.Step;
            Notches = (int[])rotor.Notches.Clone();
        }

        public static EnigmaRotor RotorI => new("EKMFLGDQVZNTOWYHXUSPAIBRCJ", ['Q']);
        public static EnigmaRotor RotorII => new("AJDKSIRUXBLHWTMCQGZNPYFVOE", ['E']);
        public static EnigmaRotor RotorIII => new("BDFHJLCPRTXVZNYEIWGAKMUSQO", ['V']);
        public static EnigmaRotor RotorIV => new("ESOVPZJAYQUIRHXLNFTGKDCMWB", ['J']);
        public static EnigmaRotor RotorV => new("VZBRGITYUPSDNHLXAWMJQOFECK", ['Z']);
        public static EnigmaRotor RotorVI => new("JPGVOUMFYQBENHZRDKASXLICTW", ['M', 'Z']);
        public static EnigmaRotor RotorVII => new("NZJHGRCXMYSWBOUFAIVLPEKQDT", ['M', 'Z']);
        public static EnigmaRotor RotorVIII => new("FKQHTLXOCBJSPDZRAMEWNIUYGV", ['M', 'Z']);
        public static EnigmaRotor RotorBeta => new("LEYJVCNIXWPBQMDRTAKZFGUHOS", []);
        public static EnigmaRotor RotorGamma => new("FSOKANUERHMBTIYCWLQPZXVGJD", []);

        public string Mapping
        {
            get => _mapping;
            set
            {
                ValidateRotorMapping(value);
                _mapping = value;
            }
        }
        public int Position
        {
            get => _position;
            set => _position = (value % AlphabetLength + AlphabetLength) % AlphabetLength;
        }
        public int? Step { get; init; }
        public int[] Notches { get; init;  }
        public bool IsAtNotch => Notches.Contains(Position);
        public Action? OnNotch { get; set; }

        public static void ValidateRotorMapping(string mapping)
        {
            if (mapping?.Length != AlphabetLength || !Alphabet.ToHashSet().SetEquals(mapping.ToHashSet()))
            {
                throw new ArgumentException("Invalid mapping.", nameof(mapping));
            }
        }

        public char Forward(char c)
        {
            return Mapping[(c - 'A' + Position) % AlphabetLength];
        }

        public char Backward(char c)
        {
            return Alphabet[(Mapping.IndexOf(c) + AlphabetLength - Position) % AlphabetLength];
        }

        public void Rotate()
        {
            int n = Step ?? 1;
            for (int i = 0; i < n; ++i)
            {
                if (IsAtNotch)
                {
                    OnNotch?.Invoke();
                }

                Position = (Position + 1) % AlphabetLength;
            }
        }
    }
    public class EnigmaReflector
    {
        private Dictionary<char, char> _mapping = null!;

        public EnigmaReflector(Dictionary<char, char> mapping)
        {
            Mapping = mapping;
        }

        public static EnigmaReflector ReflectorB => new(new Dictionary<char, char> { { 'A', 'Y' }, { 'B', 'R' }, { 'C', 'U' }, { 'D', 'H' }, { 'E', 'Q' }, { 'F', 'S' }, { 'G', 'L' }, { 'I', 'P' }, { 'J', 'X' }, { 'K', 'N' }, { 'M', 'O' }, { 'T', 'Z' }, { 'V', 'W' }, });
        public static EnigmaReflector ReflectorC => new(new Dictionary<char, char> { { 'A', 'F' }, { 'B', 'V' }, { 'C', 'P' }, { 'D', 'J' }, { 'E', 'I' }, { 'G', 'O' }, { 'H', 'Y' }, { 'K', 'R' }, { 'L', 'Z' }, { 'M', 'X' }, { 'N', 'W' }, { 'T', 'Q' }, { 'S', 'U' }, });
        public static EnigmaReflector ReflectorBDunn => new(new Dictionary<char, char> { { 'A', 'E' }, { 'B', 'N' }, { 'C', 'K' }, { 'D', 'Q' }, { 'F', 'U' }, { 'G', 'Y' }, { 'H', 'W' }, { 'I', 'J' }, { 'L', 'O' }, { 'M', 'P' }, { 'R', 'X' }, { 'S', 'Z' }, { 'T', 'V' }, });
        public static EnigmaReflector ReflectorCDunn => new(new Dictionary<char, char> { { 'A', 'R' }, { 'B', 'D' }, { 'C', 'O' }, { 'E', 'J' }, { 'F', 'N' }, { 'G', 'T' }, { 'H', 'K' }, { 'I', 'V' }, { 'L', 'M' }, { 'P', 'W' }, { 'Q', 'Z' }, { 'S', 'X' }, { 'U', 'Y' }, });

        public Dictionary<char, char> Mapping
        {
            get => _mapping;
            set
            {
                AdjustReflectorMapping(value);
                ValidateReflectorMapping(value);
                _mapping = value;
            }
        }

        public static void AdjustReflectorMapping(Dictionary<char, char> mapping)
        {
            var pairs = mapping.ToList();
            foreach (var pair in pairs)
            {
                if (!mapping.ContainsKey(pair.Value))
                {
                    mapping.Add(pair.Value, pair.Key);
                }
            }
        }
        public static void ValidateReflectorMapping(Dictionary<char, char> mapping)
        {
            var values = new HashSet<char>(mapping.Values);

            if (Alphabet.Any(c =>
                    !mapping.ContainsKey(c)
                    || mapping[c] == c
                    || !values.Contains(c)))
            {
                throw new ArgumentException("Invalid mapping.", nameof(mapping));
            }
        }

        public char Reflect(char c)
        {
            return Mapping[c];
        }
    }
}