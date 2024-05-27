namespace CryptographyLib;

using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

public static class TextSteganography
{
    public static void InjectMessageBySpaces(string containerPath, byte[] message, string outputTextPath)
    {
        string container = File.ReadAllText(containerPath);
        string[] words = container.Split(' ');

        int messageBits = (message.Length + 1) * 8;
        int containered = words.Length;

        if (messageBits > containered)
        {
            Console.WriteLine("Message is too long for this container.");
            return;
        }

        BitArray bitArray = new((message.Length + 1) * 8);
        for (int i = 0; i < message.Length; i++)
        {
            byte b = message[i];
            for (int j = 0; j < 8; j++)
            {
                bitArray.Set(i * 8 + j, (b & (1 << (7 - j))) != 0);
            }
        }
        for (int j = 0; j < 8; j++)
        {
            bitArray.Set(message.Length * 8 + j, false);
        }

        string[] modifiedWords = new string[containered];
        int currentBit = 0;
        for (int i = 0; i < containered; i++)
        {
            int spaceCount = i == containered - 1 ? 0 : 1;
            if (currentBit < bitArray.Length && bitArray[currentBit])
            {
                spaceCount++;
            }
            modifiedWords[i] = words[i] + new string(' ', spaceCount);
            currentBit++;
        }

        string newContainer = string.Join("", modifiedWords);
        File.WriteAllText(outputTextPath, newContainer);
    }

    public static byte[] GetMessageBySpaces(string textPath)
    {
        string container = File.ReadAllText(textPath);

        string pattern = @"(\S+ +)";

        MatchCollection matches = Regex.Matches(container, pattern);
        string[] words = matches.Cast<Match>().Select(x => x.Value).ToArray();

        BitArray bitArray = new(words.Length);
        for (int i = 0; i < words.Length; i++)
        {
            int spaceCount = words[i].Length - words[i].TrimEnd().Length;
            if (spaceCount == 2)
            {
                bitArray.Set(i, true);
            }
        }

        byte[] messageBytes = new byte[bitArray.Length / 8];
        for (int i = 0; i < messageBytes.Length; i++)
        {
            byte b = 0;
            for (int j = 0; j < 8; j++)
            {
                if (bitArray.Get(i * 8 + j))
                {
                    b |= (byte)(1 << (7 - j));
                }
            }
            messageBytes[i] = b;
        }

        int terminatorIndex = Array.IndexOf(messageBytes, (byte)0);
        if (terminatorIndex != -1)
        {
            messageBytes = messageBytes.Take(terminatorIndex).ToArray();
        }

        return messageBytes;
    }
}