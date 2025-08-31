using nebulae.dotChaCha20;

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
    }
}