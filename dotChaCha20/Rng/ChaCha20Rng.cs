using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotChaCha20.Rng;

/// <summary>
/// Represents a cryptographically secure pseudo-random number generator (CSPRNG) based on the ChaCha20 stream cipher.
/// </summary>
/// <remarks>This RNG generates random numbers using the ChaCha20 stream cipher, which is known for its high
/// performance and strong security properties. It supports reseeding with a custom seed, cloning to create independent
/// RNG instances with the same state, and jumping ahead in the random sequence.</remarks>
public sealed class ChaCha20Rng : BaseRng
{
    private readonly byte[] _key = new byte[32];
    private readonly byte[] _nonce = new byte[12];

    private readonly byte[] _buffer = new byte[64];
    private int _offset = 64;
    private uint _counter;

    /// <summary>
    /// Initializes a new instance of the <see cref="ChaCha20Rng"/> class.
    /// </summary>
    /// <remarks>The constructor automatically reseeds the random number generator to ensure it starts with a
    /// new state.</remarks>
    public ChaCha20Rng()
    {
        Reseed();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ChaCha20Rng"/> class using the specified seed.
    /// </summary>
    /// <remarks>The provided seed initializes the internal state of the ChaCha20 random number generator.  A
    /// strong, unique seed is recommended to ensure the unpredictability of the generated random numbers.</remarks>
    /// <param name="seed">A read-only span of bytes used to seed the random number generator. The seed must be at least 32 bytes long.</param>
    public ChaCha20Rng(ReadOnlySpan<byte> seed)
    {
        Reseed(seed);
    }

    /// <summary>
    /// Generates the next 64-bit unsigned integer from the internal buffer.
    /// </summary>
    /// <remarks>This method retrieves an unsigned 64-bit integer from the current position in the buffer. If
    /// the buffer does not have enough data to fulfill the request, it is refilled before proceeding.</remarks>
    /// <returns>A 64-bit unsigned integer generated from the internal buffer.</returns>
    public override ulong NextRaw64()
    {
        if (_offset > 56)
        {
            Refill();
        }

        ulong result = BinaryPrimitives.ReadUInt64LittleEndian(_buffer.AsSpan(_offset));
        _offset += 8;
        return result;
    }

    private void Refill()
    {
        ChaCha20.Encrypt(_key, _nonce, _counter, new byte[64], _buffer);

        _counter++;

        if (_counter == 0) // wrapped!
        {
            // Advance nonce (big-endian)
            for (int i = 11; i >= 0; i--)
            {
                if (++_nonce[i] != 0)
                    break;
            }
        }

        _offset = 0;
    }

    /// <summary>
    /// Reseeds the internal state of the random number generator with new cryptographic entropy.
    /// </summary>
    /// <remarks>This method generates a new key, nonce, and resets the counter to ensure the generator's
    /// state is refreshed.  It is recommended to call this method periodically to maintain the cryptographic strength
    /// of the generator.</remarks>
    public override void Reseed()
    {
        Span<byte> seed = stackalloc byte[44];
        RandomNumberGenerator.Fill(seed);

        seed[..32].CopyTo(_key);
        seed.Slice(32, 12).CopyTo(_nonce);
        _counter = 0;
        _offset = 64; // force immediate refill
    }

    /// <summary>
    /// Reseeds the internal state of the cryptographic generator with a new seed value.
    /// </summary>
    /// <remarks>This method resets the internal counter and forces an immediate refill of the generator's
    /// state. Ensure that the provided seed meets the required length and structure to maintain the integrity of the
    /// cryptographic operations.</remarks>
    /// <param name="seed">A read-only span of bytes containing the new seed. The seed must be at least 44 bytes long, consisting of 32
    /// bytes for the key and 12 bytes for the nonce.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="seed"/> is less than 44 bytes in length.</exception>
    public void Reseed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length < 44)
            throw new ArgumentException("Seed must be at least 44 bytes (32 key + 12 nonce)");
    
        seed[..32].CopyTo(_key);
        seed.Slice(32, 12).CopyTo(_nonce);
        _counter = 0;
        _offset = 64; // force immediate refill
    }

    /// <summary>
    /// Creates a new instance of the random number generator with the same internal state as the current instance.
    /// </summary>
    /// <remarks>The cloned instance will produce the same sequence of random numbers as the original
    /// instance, starting from its current state.</remarks>
    /// <returns>A new <see cref="INebulaeRng"/> instance that is a clone of the current random number generator.</returns>
    public override INebulaeRng Clone()
    {
        var clone = new ChaCha20Rng();
        _key.CopyTo(clone._key, 0);
        _nonce.CopyTo(clone._nonce, 0);
        _buffer.CopyTo(clone._buffer, 0);
        clone._offset = _offset;
        clone._counter = _counter;
        return clone;
    }

    /// <summary>
    /// Jumps ahead to the next 256GB block of random data by incrementing the 96-bit nonce.
    /// </summary>
    public override void Jump()
    {
        // Increment 96-bit nonce as big-endian integer
        for (int i = 11; i >= 0; i--)
        {
            if (++_nonce[i] != 0)
                break;
        }

        _counter = 0;
        _offset = 64; // force refill
    }
}
