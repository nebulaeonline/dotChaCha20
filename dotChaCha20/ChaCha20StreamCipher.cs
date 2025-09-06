using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotChaCha20;

/// <summary>
/// Provides an implementation of the ChaCha20 stream cipher for encrypting and decrypting data.
/// </summary>
/// <remarks>The ChaCha20 stream cipher is a high-speed, secure encryption algorithm designed for symmetric key
/// cryptography. This class supports encryption and decryption of data in both in-memory buffers and streams. The same
/// method is used for both encryption and decryption, as the operation is symmetric.  To use this class, initialize it
/// with a 32-byte key, an 8- or 12-byte nonce, and an optional initial counter value. The <see
/// cref="Transform(ReadOnlySpan{byte}, Span{byte})"/> method can be used for in-memory transformations, while the <see
/// cref="Transform(Stream, Stream, int)"/> method is suitable for processing data streams.</remarks>
public sealed class ChaCha20StreamCipher
{
    private readonly byte[] _key = new byte[32];
    private readonly byte[] _nonce;
    private uint _counter;

    /// <summary>
    /// Initializes a new instance of the <see cref="ChaCha20StreamCipher"/> class with the specified key, nonce, and
    /// initial counter.
    /// </summary>
    /// <remarks>The ChaCha20 stream cipher is a symmetric encryption algorithm designed for high performance
    /// and security. Ensure that the combination of <paramref name="key"/> and <paramref name="nonce"/> is unique for
    /// each encryption stream to maintain security.</remarks>
    /// <param name="key">The 256-bit (32-byte) key used for encryption and decryption. The key must be exactly 32 bytes in length.</param>
    /// <param name="nonce">The nonce (number used once) used to ensure unique encryption streams. The nonce must be either 8 or 12 bytes in
    /// length.</param>
    /// <param name="initialCounter">The initial counter value for the cipher. Defaults to 0 if not specified. This value is used to derive the
    /// initial state of the cipher.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not 32 bytes in length, or if <paramref name="nonce"/> is not 8 or 12 bytes
    /// in length.</exception>
    public ChaCha20StreamCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint initialCounter = 0)
    {
        if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.");
        if (nonce.Length != 8 && nonce.Length != 12) throw new ArgumentException("Nonce must be 8 or 12 bytes.");

        key.CopyTo(_key);
        _nonce = nonce.ToArray();
        _counter = initialCounter;
    }

    /// <summary>
    /// Transforms the input data by encrypting or decrypting it using the ChaCha20 algorithm.
    /// </summary>
    /// <remarks>This method processes the input data in 64-byte blocks and updates the internal counter
    /// accordingly.  The transformation is performed in-place, meaning the output span will contain the transformed
    /// data.</remarks>
    /// <param name="input">The input data to be transformed. The length of this span must match the length of <paramref name="output"/>.</param>
    /// <param name="output">The span where the transformed data will be written. The length of this span must match the length of <paramref
    /// name="input"/>.</param>
    /// <exception cref="ArgumentException">Thrown if the lengths of <paramref name="input"/> and <paramref name="output"/> do not match.</exception>
    public void Transform(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length != output.Length)
            throw new ArgumentException("Input/output lengths must match.");

        ChaCha20.Encrypt(_key, _nonce, _counter, input, output);

        // Advance counter by number of 64-byte blocks
        _counter += (uint)((input.Length + 63) / 64);
    }

    /// <summary>
    /// Transforms data from the input stream and writes the transformed data to the output stream.
    /// </summary>
    /// <remarks>This method processes the input stream in chunks of the specified buffer size. The
    /// transformation is applied  to each chunk before writing it to the output stream. The caller is responsible for
    /// ensuring that the input  and output streams are properly opened and disposed.</remarks>
    /// <param name="input">The input stream containing the data to be transformed. The stream must be readable.</param>
    /// <param name="output">The output stream where the transformed data will be written. The stream must be writable.</param>
    /// <param name="bufferSize">The size of the buffer, in bytes, used to read and write data. The default value is 8192.</param>
    public void Transform(Stream input, Stream output, int bufferSize = 8192)
    {
        byte[] inBuf = new byte[bufferSize];
        byte[] outBuf = new byte[bufferSize];

        int bytesRead;
        while ((bytesRead = input.Read(inBuf, 0, inBuf.Length)) > 0)
        {
            Transform(inBuf.AsSpan(0, bytesRead), outBuf.AsSpan(0, bytesRead));
            output.Write(outBuf, 0, bytesRead);
        }
    }
}

