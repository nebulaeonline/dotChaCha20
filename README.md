# dotChaCha20

A minimal, fast, cross-platform ChaCha20 wrapper for .NET applications.

This library provides access to the ChaCha20 stream cipher, which is known for its speed and security. It is designed to be easy to use and integrates seamlessly with .NET applications. Binaries are provided for Windows x64, Linux x64 and macOS (x64 & Apple Silicon).

The underlying optimized implementation is taken verbatim from BoringSSL maintained by Google, ensuring that it is both efficient and secure.

Tests are included and available in the Github repo.

[![NuGet](https://img.shields.io/nuget/v/nebulae.dotChaCha20.svg)](https://www.nuget.org/packages/nebulae.dotChaCha20)

---

## Features

- **Cross-platform**: Works on Windows, Linux, and macOS (x64 & Apple Silicon).
- **High performance**: Optimized for speed, leveraging AVX2 on x64 & neon on Apple Silicon.
- **Easy to use**: Simple API for encryption and decryption.
- **Secure**: Based on the ChaCha20 cipher, which is widely recognized for its security.
- **Minimal dependencies**: No external dependencies required (all are included), making it lightweight and easy to integrate.

---

## Requirements

- .NET 8.0 or later
- Advanced SIMD capable CPU (AVX2 support for x64 on any OS or neon on Apple Silicon M-Series)
- Windows x64, Linux x64, or macOS (x64 / M-series arm64)

## Usage

For those that are unaware, ChaCha20 is a stream ciper that is used for encrypting data in a way that is both fast and secure. It operates on 64-byte blocks and uses a 256-bit key. The encrypt function called with the key & nonce will encrypt the plaintext (the message), and re-running the encrypt function with the same key & nonce on the encrypted message will yield the original plaintext.

```csharp

using System;
using nebulae.dotChaCha20;

public class Example
{
    public static void Main()
    {
        // Be sure to call Init() to load the native library (no longer required as of v0.1.10)
        // ChaCha20.Init();

        // ------------------------
        //  Example 1: byte[] API
        // ------------------------
        byte[] key1 = new byte[32];
        byte[] nonce1 = new byte[12];
        byte[] plaintext1 = new byte[32];
        new Random(1).NextBytes(plaintext1); // fill with random data

        byte[] ciphertext1 = new byte[32];
        byte[] decrypted1 = new byte[32];

        ChaCha20.Encrypt(key1, nonce1, counter: 1, plaintext1, ciphertext1);
        ChaCha20.Encrypt(key1, nonce1, counter: 1, ciphertext1, decrypted1);

        Console.WriteLine("Byte[] round-trip success: " + plaintext1.AsSpan().SequenceEqual(decrypted1));

        // ------------------------------
        //  Example 2: Span<byte> API
        // ------------------------------
        Span<byte> key2 = stackalloc byte[32];
        Span<byte> nonce2 = stackalloc byte[12];
        Span<byte> plaintext2 = stackalloc byte[32];
        Span<byte> ciphertext2 = stackalloc byte[32];
        Span<byte> decrypted2 = stackalloc byte[32];

        new Random(2).NextBytes(plaintext2);

        ChaCha20.Encrypt(key2, nonce2, counter: 1, plaintext2, ciphertext2);
        ChaCha20.Encrypt(key2, nonce2, counter: 1, ciphertext2, decrypted2);

        Console.WriteLine("Span<byte> round-trip success: " + plaintext2.SequenceEqual(decrypted2));
    }
}

```

---

## Installation

You can install the package via NuGet:

```bash

$ dotnet add package nebulae.dotChaCha20

```

Or via git:

```bash

$ git clone https://github.com/nebulaeonline/dotChaCha20.git
$ cd dotChaCha20
$ dotnet build

```

---

## License

MIT

## Roadmap

Unless there are vulnerabilities found in the ChaCha20 cipher, there are no plans to add any new features.