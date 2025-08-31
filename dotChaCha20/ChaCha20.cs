using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotChaCha20
{
    public static class ChaCha20
    {
        static ChaCha20()
        {
            Init();
        }

        /// <summary>
        /// Initializes the ChaCha20 cryptographic library.
        /// </summary>
        /// <remarks>This method must be called before using any functionality provided by the ChaCha20
        /// library. It ensures that the library is properly set up and ready for cryptographic operations.</remarks>
        public static void Init()
        {
            ChaCha20Library.Init();
        }

        /// <summary>
        /// Span-based function to encrypt the input data using the ChaCha20 encryption algorithm.
        /// </summary>
        /// <remarks>This method performs encryption using the ChaCha20 algorithm, which is a stream
        /// cipher designed for high performance and security. The caller must ensure that the key, nonce, and
        /// input/output buffers meet the required constraints.</remarks>
        /// <param name="key">A 32-byte key used for encryption. The key must be exactly 32 bytes long.</param>
        /// <param name="nonce">A nonce used for encryption. The nonce must be either 8 or 12 bytes long.</param>
        /// <param name="counter">The initial counter value for the ChaCha20 algorithm. This value is typically set to 0 for new encryption
        /// operations.</param>
        /// <param name="input">The input data to be encrypted. The length of the input must match the length of the output buffer.</param>
        /// <param name="output">A buffer to store the encrypted output data. The length of the output buffer must match the length of the
        /// input data.</param>
        /// <exception cref="ArgumentException">Thrown if the <paramref name="key"/> is not 32 bytes long, if the <paramref name="nonce"/> is not 8 or 12
        /// bytes long, or if the lengths of <paramref name="input"/> and <paramref name="output"/> do not match.</exception>
        /// <exception cref="InvalidOperationException">Thrown if the underlying encryption operation fails.</exception>
        public static void Encrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            uint counter,
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            if (key.Length != 32)
                throw new ArgumentException("ChaCha20 key must be 32 bytes.");
            if (nonce.Length != 8 && nonce.Length != 12)
                throw new ArgumentException("ChaCha20 nonce must be 8 or 12 bytes.");
            if (input.Length != output.Length)
                throw new ArgumentException("Input and output lengths must match.");

            unsafe
            {
                fixed (byte* k = key)
                fixed (byte* n = nonce)
                fixed (byte* i = input)
                fixed (byte* o = output)
                {
                    int result = ChaCha20Interop.chacha20_encrypt_ptr(
                        k, n, counter, i, o, (UIntPtr)input.Length);

                    if (result != 0)
                        throw new InvalidOperationException($"chacha20_encrypt_ptr returned error code {result}");
                }
            }
        }

        /// <summary>
        /// Encrypts the input data using the ChaCha20 encryption algorithm.
        /// </summary>
        /// <remarks>This method performs encryption using the ChaCha20 algorithm, which is a stream
        /// cipher designed for high performance and security. The caller must ensure that the input and output buffers
        /// are of the same length, as the encrypted data is written directly to the output buffer.</remarks>
        /// <param name="key">The encryption key, which must be a 32-byte array. This key is used to initialize the ChaCha20 cipher.</param>
        /// <param name="nonce">The nonce, which must be either an 8-byte or 12-byte array. The nonce ensures that the encryption is unique
        /// for each operation.</param>
        /// <param name="counter">The initial counter value for the ChaCha20 algorithm. This value is typically set to 0 for most use cases.</param>
        /// <param name="input">The input data to be encrypted. This array contains the plaintext data that will be transformed into
        /// ciphertext.</param>
        /// <param name="output">The output buffer where the encrypted data will be written. This array must be the same length as the input
        /// array.</param>
        /// <exception cref="ArgumentNullException">Thrown if any of the arguments <paramref name="key"/>, <paramref name="nonce"/>, <paramref name="input"/>,
        /// or <paramref name="output"/> are null.</exception>
        /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not 32 bytes, <paramref name="nonce"/> is not 8 or 12 bytes, or if
        /// <paramref name="input"/> and <paramref name="output"/> have different lengths.</exception>
        /// <exception cref="InvalidOperationException">Thrown if the underlying ChaCha20 encryption operation fails.</exception>
        public static void Encrypt(
            byte[] key,
            byte[] nonce,
            uint counter,
            byte[] input,
            byte[] output)
        {
            if (key == null || nonce == null || input == null || output == null)
                throw new ArgumentNullException("Arguments cannot be null.");

            if (key.Length != 32)
                throw new ArgumentException("ChaCha20 key must be 32 bytes.");
            if (nonce.Length != 8 && nonce.Length != 12)
                throw new ArgumentException("Nonce must be 8 or 12 bytes.");
            if (input.Length != output.Length)
                throw new ArgumentException("Input and output lengths must match.");

            int result = ChaCha20Interop.chacha20_encrypt(
                key, nonce, counter, input, output, (UIntPtr)input.Length);

            if (result != 0)
                throw new InvalidOperationException($"chacha20_encrypt returned error code {result}");
        }
    }
}
