#pragma warning disable CA1416 // Validate platform compatibility

namespace Cryptography;

using System;
using System.Drawing;
using System.Drawing.Imaging;

public static class ImageSteganography
{
    public static void InjectMessageByRows(string containerPath, byte[] message, string outputImagePath)
    {
        using Bitmap container = new(containerPath);
        int maxMessageBits = container.Width * container.Height * 3;
        if (message.Length * 8 > maxMessageBits)
            throw new ArgumentOutOfRangeException(nameof(message), "The message is too long for the given container");

        int messageBitIndex = 0;
        for (int y = 0; y < container.Height; y++)
        {
            for (int x = 0; x < container.Width; x++)
            {
                Color pixel = container.GetPixel(x, y);
                byte[] pixelBytes = { pixel.R, pixel.G, pixel.B };

                ProcessPixel(message, ref messageBitIndex, pixelBytes);

                Color newPixel = Color.FromArgb(pixelBytes[0], pixelBytes[1], pixelBytes[2]);
                container.SetPixel(x, y, newPixel);

                if (messageBitIndex >= message.Length * 8)
                    break;
            }

            if (messageBitIndex >= message.Length * 8)
                break;
        }

        container.Save(outputImagePath, ImageFormat.Png);
    }

    public static byte[] GetMessageByRows(string imagePath)
    {
        using Bitmap container = new(imagePath);
        int messageBitsLength = container.Width * container.Height * 3;

        byte[] messageBytes = new byte[(messageBitsLength + 7) / 8];
        int messageBitIndex = 0;
        bool stopExtraction = false;

        for (int y = 0; y < container.Height; y++)
        {
            for (int x = 0; x < container.Width; x++)
            {
                Color pixel = container.GetPixel(x, y);
                byte[] pixelBytes = { pixel.R, pixel.G, pixel.B };

                ExtractMessageBits(pixelBytes, ref messageBitIndex, messageBytes, messageBitsLength, ref stopExtraction);
                if (stopExtraction)
                    break;
            }

            if (stopExtraction)
                break;
        }

        int nullTerminatorIndex = Array.IndexOf(messageBytes, (byte)0);
        if (nullTerminatorIndex != -1)
            messageBytes = messageBytes.Take(nullTerminatorIndex).ToArray();
        return messageBytes;
    }

    public static void InjectMessageByColumns(string containerPath, byte[] message, string outputImagePath)
    {
        using Bitmap container = new(containerPath);
        int maxMessageBits = container.Width * container.Height * 3;
        if (message.Length * 8 > maxMessageBits)
            throw new ArgumentOutOfRangeException(nameof(message), "The message is too long for the given container.");

        int messageBitIndex = 0;
        for (int x = 0; x < container.Width; x++)
        {
            for (int y = 0; y < container.Height; y++)
            {
                Color pixel = container.GetPixel(x, y);
                byte[] pixelBytes = { pixel.R, pixel.G, pixel.B };

                ProcessPixel(message, ref messageBitIndex, pixelBytes);

                Color newPixel = Color.FromArgb(pixelBytes[0], pixelBytes[1], pixelBytes[2]);
                container.SetPixel(x, y, newPixel);

                if (messageBitIndex >= message.Length * 8)
                    break;
            }

            if (messageBitIndex >= message.Length * 8)
                break;
        }

        container.Save(outputImagePath, ImageFormat.Png);
    }

    public static byte[] GetMessageByColumns(string imagePath)
    {
        using Bitmap container = new(imagePath);
        int messageBitsLength = container.Width * container.Height * 3;

        byte[] messageBytes = new byte[(messageBitsLength + 7) / 8];
        int messageBitIndex = 0;
        bool stopExtraction = false;

        for (int x = 0; x < container.Width; x++)
        {
            for (int y = 0; y < container.Height; y++)
            {
                Color pixel = container.GetPixel(x, y);
                byte[] pixelBytes = { pixel.R, pixel.G, pixel.B };

                ExtractMessageBits(pixelBytes, ref messageBitIndex, messageBytes, messageBitsLength, ref stopExtraction);

                if (stopExtraction)
                    break;
            }

            if (messageBitIndex >= messageBitsLength)
                break;
        }

        int nullTerminatorIndex = Array.IndexOf(messageBytes, (byte)0);
        if (nullTerminatorIndex != -1)
            messageBytes = messageBytes.Take(nullTerminatorIndex).ToArray();
        return messageBytes;
    }

    private static void ProcessPixel(byte[] message, ref int messageBitIndex, byte[] pixelBytes)
    {
        for (int i = 0; i < 3; i++)
        {
            if (messageBitIndex >= message.Length * 8)
                return;

            byte pixelByte = pixelBytes[i];
            bool messageBit = (message[messageBitIndex / 8] & (1 << (messageBitIndex % 8))) != 0;
            pixelByte = (byte)((pixelByte & 0xFE) | (messageBit ? 1 : 0));
            pixelBytes[i] = pixelByte;
            messageBitIndex++;
        }
    }

    private static void ExtractMessageBits(byte[] pixelBytes, ref int messageBitIndex, byte[] messageBytes, int messageBitsLength, ref bool stopExtraction)
    {
        for (int i = 0; i < 3; i++)
        {
            if (stopExtraction || messageBitIndex >= messageBitsLength)
                return;

            byte pixelByte = pixelBytes[i];
            byte messageBit = (byte)((pixelByte & 1) != 0 ? 1 : 0);
            messageBytes[messageBitIndex / 8] |= (byte)(messageBit << (messageBitIndex % 8));
            messageBitIndex++;

            if (messageBitIndex % 8 == 0 && messageBytes[messageBitIndex / 8 - 1] == 0)
            {
                stopExtraction = true;
                return;
            }
        }
    }

    public static void BuildColorMatrix(string imagePath, string outputPath)
    {
        using Bitmap originalImage = new(imagePath);
        Bitmap newImage = new(originalImage.Width, originalImage.Height);

        for (int y = 0; y < originalImage.Height; y++)
        {
            for (int x = 0; x < originalImage.Width; x++)
            {
                Color pixel = originalImage.GetPixel(x, y);

                byte blue = (byte)(pixel.B & 0x01);
                byte green = (byte)(pixel.G & 0x01);
                byte red = (byte)(pixel.R & 0x01);

                Color newPixel = Color.FromArgb(red * 255, green * 255, blue * 255);
                newImage.SetPixel(x, y, newPixel);
            }
        }

        newImage.Save(outputPath, ImageFormat.Png);
    }
}