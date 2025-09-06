using nebulae.dotChaCha20;
using nebulae.dotChaCha20.Rng;

namespace nebulae.dotChaCha20Tests
{
    public class dotChaCha20Tests
    {
        [Fact]
        public void Encrypt_KnownVector_Rfc8439()
        {
            //ChaCha20.Init();

            byte[] key = Convert.FromHexString(
                "000102030405060708090A0B0C0D0E0F" +
                "101112131415161718191A1B1C1D1E1F");

            byte[] nonce = Convert.FromHexString(
                "000000090000004A00000000");

            uint counter = 1;

            byte[] input = new byte[64]; // all zero input
            byte[] output = new byte[64];

            byte[] expected = Convert.FromHexString(
                "10F1E7E4D13B5915500FDD1FA32071C4" +
                "C7D1F4C733C068030422AA9AC3D46C4E" +
                "D2826446079FAA0914C2D705D98B02A2" +
                "B5129CD1DE164EB9CBD083E8A2503C4E");

            ChaCha20.Encrypt(key, nonce, counter, input, output);

            Assert.Equal(expected, output);
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip_ByteArray()
        {
            //ChaCha20.Init();

            var key = new byte[32];
            var nonce = new byte[12];
            var plaintext = new byte[64];
            new Random(42).NextBytes(plaintext); // deterministic

            var ciphertext = new byte[64];
            var decrypted = new byte[64];

            // Encrypt
            ChaCha20.Encrypt(key, nonce, 1, plaintext, ciphertext);
            Assert.NotEqual(plaintext, ciphertext); // sanity check

            // Decrypt (same function)
            ChaCha20.Encrypt(key, nonce, 1, ciphertext, decrypted);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip_SpanBased()
        {
            //ChaCha20.Init();

            Span<byte> key = stackalloc byte[32];
            Span<byte> nonce = stackalloc byte[12];
            Span<byte> plaintext = stackalloc byte[64];
            Span<byte> ciphertext = stackalloc byte[64];
            Span<byte> decrypted = stackalloc byte[64];

            new Random(1337).NextBytes(plaintext); // deterministic

            // Encrypt
            ChaCha20.Encrypt(key, nonce, 1, plaintext, ciphertext);
            Assert.False(ciphertext.SequenceEqual(plaintext));

            // Decrypt
            ChaCha20.Encrypt(key, nonce, 1, ciphertext, decrypted);
            Assert.True(decrypted.SequenceEqual(plaintext));
        }

        [Fact]
        public void ChaCha20Rng_DeterministicOutput_FromSeed()
        {
            byte[] seed = new byte[44];
            for (int i = 0; i < 44; i++) seed[i] = (byte)i;

            var rng1 = new ChaCha20Rng(seed);
            var rng2 = new ChaCha20Rng(seed);

            for (int i = 0; i < 1000; i++)
            {
                Assert.Equal(rng1.NextRaw64(), rng2.NextRaw64());
            }
        }

        [Fact]
        public void ChaCha20Rng_Clone_ProducesSameStream()
        {
            byte[] seed = new byte[44];
            new Random(1234).NextBytes(seed);

            var rng1 = new ChaCha20Rng(seed);
            var rng2 = (ChaCha20Rng)rng1.Clone();

            for (int i = 0; i < 1000; i++)
            {
                Assert.Equal(rng1.NextRaw64(), rng2.NextRaw64());
            }
        }

        [Fact]
        public void ChaCha20Rng_Jump_ChangesOutputStream()
        {
            byte[] seed = Enumerable.Range(0, 44).Select(i => (byte)i).ToArray();
            var rng1 = new ChaCha20Rng(seed);
            var rng2 = new ChaCha20Rng(seed);

            rng2.Jump(); // should now be in a different substream

            // First few values should differ
            bool mismatch = false;
            for (int i = 0; i < 20; i++)
            {
                if (rng1.NextRaw64() != rng2.NextRaw64())
                {
                    mismatch = true;
                    break;
                }
            }

            Assert.True(mismatch, "Jump() did not advance stream to a new disjoint substream.");
        }

        [Fact]
        public void ChaCha20Rng_RefillsCorrectly_AcrossBuffer()
        {
            byte[] seed = new byte[44];
            new Random(5678).NextBytes(seed);
            var rng = new ChaCha20Rng(seed);

            var values = new ulong[10];

            for (int i = 0; i < 10; i++)
                values[i] = rng.NextRaw64();

            // No crash, no duplication, and values appear valid
            Assert.Equal(10, values.Distinct().Count());
        }

        [Fact]
        public void ChaCha20Rng_RangedValuesStayInBounds()
        {
            var rng = new ChaCha20Rng();

            for (int i = 0; i < 1000; i++)
            {
                byte b = rng.Rand8(200);
                Assert.InRange(b, 0, 200);

                ushort s = rng.Rand16(60000);
                Assert.InRange(s, 0, 60000);

                uint u = rng.Rand32(1000000);
                Assert.InRange(u, 0U, 1000000U);

                ulong ul = rng.Rand64(1_000_000_000_000UL);
                Assert.InRange(ul, 0UL, 1_000_000_000_000UL);
            }
        }
    }
}