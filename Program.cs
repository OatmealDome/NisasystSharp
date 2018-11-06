using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace NisasystSharp
{
    internal class Program
    {
        private static readonly char[] KeyMaterial =
        {
            'e', '4', '1', '3', '6', '4', '5', 'f', 'a', '6', '9', 'c', 'a', 'f', 'e', '3',
            '4', 'a', '7', '6', '1', '9', '2', '8', '4', '3', 'e', '4', '8', 'c', 'b', 'd',
            '6', '9', '1', 'd', '1', 'f', '9', 'f', 'b', 'a', '8', '7', 'e', '8', 'a', '2',
            '3', 'd', '4', '0', 'e', '0', '2', 'c', 'e', '1', '3', 'b', '0', 'd', '5', '3',
            '4', 'd', '1', '0', '3', '0', '1', '5', '7', '6', 'f', '3', '1', 'b', 'c', '7',
            '0', 'b', '7', '6', '3', 'a', '6', '0', 'c', 'f', '0', '7', '1', '4', '9', 'c',
            'f', 'c', 'a', '5', '0', 'e', '2', 'a', '6', 'b', '3', '9', '5', '5', 'b', '9',
            '8', 'f', '2', '6', 'c', 'a', '8', '4', 'a', '5', '8', '4', '4', 'a', '8', 'a',
            'e', 'c', 'a', '7', '3', '1', '8', 'f', '8', 'd', '7', 'd', 'b', 'a', '4', '0',
            '6', 'a', 'f', '4', 'e', '4', '5', 'c', '4', '8', '0', '6', 'f', 'a', '4', 'd',
            '7', 'b', '7', '3', '6', 'd', '5', '1', 'c', 'c', 'e', 'a', 'a', 'f', '0', 'e',
            '9', '6', 'f', '6', '5', '7', 'b', 'b', '3', 'a', '8', 'a', 'f', '9', 'b', '1',
            '7', '5', 'd', '5', '1', 'b', '9', 'b', 'd', 'd', 'c', '1', 'e', 'd', '4', '7',
            '5', '6', '7', '7', '2', '6', '0', 'f', '3', '3', 'c', '4', '1', 'd', 'd', 'b',
            'c', '1', 'e', 'e', '3', '0', 'b', '4', '6', 'c', '4', 'd', 'f', '1', 'b', '2',
            '4', 'a', '2', '5', 'c', 'f', '7', 'c', 'b', '6', '0', '1', '9', '7', '9', '4'
        };

        private static void Main(string[] args)
        {
            // Check if enough args were passed
            if (args.Length != 2)
            {
                Console.WriteLine("NisasystSharp <game path> <file path>" +
                "\nExample: NisasystSharp Mush/ActorDb.release.byml C:\\Blitz\\ActorDb.Release.byml");
                return;
            }

            using (var file = File.OpenRead(args[1]))
            using (var reader = new BinaryReader(file))
            {
                // Length of the file, minus the "nisasyst" magic
                var len = (int)file.Length - 8;

                // Seek to the magic numbers
                file.Position = len;

                // Verify the magic numbers
                if (reader.ReadUInt64() != 0x747379736173696e)
                {
                    // This isn't a valid file
                    Console.WriteLine("This file isn't a nisasyst container");
                    return;
                }

                // Move back to the beginning of the file
                file.Position = 0;

                // Create a CRC32 over the game path, and a new SeadRandom instance using the seed
                var seadRandom = new SeadRand(Crc32(args[0]));

                // Create the encryption key and IV
                byte[] key = CreateSequence(seadRandom), iv = CreateSequence(seadRandom);

                using (var ms = new MemoryStream())
                using (var aes = new AesCryptoServiceProvider() { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
                {
                    using (var crypt = aes.CreateDecryptor(key, iv))
                        File.WriteAllBytes($"{args[1]}.decrypted", crypt.TransformFinalBlock(reader.ReadBytes(len), 0, len));

                    Console.WriteLine("Wrote decrypted file");
                }
            }
        }

        private static byte[] CreateSequence(SeadRand random)
        {
            // Create byte array
            var sequence = new byte[16];

            // Create each byte
            for (int i = 0; i < sequence.Length; i++)
            {
                // Create empty byte string
                var byteString = string.Empty;

                // Get characters from key material
                byteString += KeyMaterial[random.GetU32() >> 24];
                byteString += KeyMaterial[random.GetU32() >> 24];

                // Parse the resulting byte
                sequence[i] = Convert.ToByte(byteString, 16);
            }

            // Return the sequence
            return sequence;
        }

        private static uint Crc32(string input)
        {
            // Compute the lookup table
            uint[] table = Enumerable.Range(0, 256).Select(i =>
            {
                var tableEntry = (uint)i;
                for (var j = 0; j < 8; ++j)
                    tableEntry = ((tableEntry & 1) != 0) ? (0xedb88320 ^ (tableEntry >> 1)) : (tableEntry >> 1);
                return tableEntry;
            }).ToArray();

            // Compute the CRC value
            return ~input.Aggregate(0xffffffff, (idx, b) => (table[(idx & 0xff) ^ b] ^ (idx >> 8)));
        }

        // Generate the pseudorandom seed using Splatoon 2's mersenne twister
        internal class SeadRand
        {
            private readonly uint[] state = new uint[4];

            public SeadRand(uint seed)
            {
                for (int i = 0; i < 4; i++)
                    seed = state[i] = (uint)(0x6c078965 * (seed ^ (seed >> 30)) + i + 1);
            }

            public uint GetU32()
            {
                uint a = state[0] ^ (state[0] << 11), b = state[3], c = a ^ (a >> 8) ^ b ^ (b >> 19);
                for (int i = 0; i < 3; i++)
                    state[i] = state[i + 1];
                return state[3] = c;
            }
        }
    }
}