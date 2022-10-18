using System.Text;

namespace TZPD_Assignment2;

internal static class Program
{
    public static void Main(string[] args)
    {
        const int hashLength = 256;
        var initialInput = GenerateInputData('#');
        var stringData = ConvertInputDataToString(initialInput);
        var dataBytes = GetStringDataBytes(stringData);

        var alice = new Actor();
        var bob = new Actor();

        var dataBytesChunks = dataBytes.Chunk(32);
        var encryptedData = new byte[32768];

        var index = 0;
        foreach (var chunk in dataBytesChunks)
        {
            var encryptedChunk = alice.Encrypt(bob.PublicKey, chunk);
            foreach (var b in encryptedChunk)
            {
                encryptedData[index] = b;
                index++;
            }
        }

        index = 0;

        var hashedEncryptedData = alice.Hash(encryptedData, hashLength);
        var signature = alice.Sign(hashedEncryptedData);
        var decryptedData = new byte[encryptedData.Length];

        var isValid = bob.VerifySignature(alice.PublicKey, hashedEncryptedData, signature);
        if (isValid)
        {
            var encryptedDataChunks = encryptedData.Chunk(256);
            foreach (var chunk in encryptedDataChunks)
            {
                var decryptedChunk = bob.DecryptData(chunk);
                foreach (var b in decryptedChunk)
                {
                    decryptedData[index] = b;
                    index++;
                }
            }
        }
        else
        {
            Console.WriteLine("Signature is not valid");
        }

        WriteLine("Input", stringData);
        WriteLine("Encrypted input", BitConverter.ToString(encryptedData).Replace("-", string.Empty));
        WriteLine("Hashed encrypted input", BitConverter.ToString(hashedEncryptedData).Replace("-", string.Empty));
        WriteLine("Signature", BitConverter.ToString(signature).Replace("-", string.Empty));
        WriteLine("Decrypted data", Encoding.UTF8.GetString(decryptedData));

        Console.Read();
    }

    private static char[,] GenerateInputData(char delimiter)
    {
        var seed = (int)DateTime.UtcNow.Ticks;
        var random = new Random(seed);
        var data = new char[64, 64];
        var allowedChars = new[] { '0', '1' };

        for (var i = 0; i < data.GetLength(0); i++)
        {
            for (var j = 0; j < data.GetLength(1); j++)
            {
                if (i == data.GetLength(0) / 2 && j == data.GetLength(1) / 2)
                {
                    data[i, j] = delimiter;
                    continue;
                }

                data[i, j] = allowedChars[random.Next(0, 2)];
            }
        }

        return data;
    }

    private static string ConvertInputDataToString(char[,] data)
    {
        var stringBuilder = new StringBuilder();
        foreach (var c in data)
        {
            stringBuilder.Append(c);
        }

        return stringBuilder.ToString();
    }

    private static IEnumerable<byte> GetStringDataBytes(string data)
        => Encoding.UTF8.GetBytes(data);

    private static void WriteLine(string title, string text)
    {
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine(title);

        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine(text);

        Console.WriteLine();
    }
}
