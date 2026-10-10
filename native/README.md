# Native ChaCha20 builds

The native library is deliberately built from only two source files:

- `chacha20_export.cc`, the project-owned shim that exports the .NET
  `chacha20_encrypt` entry point.
- One generated BoringSSL ChaCha assembly file for the target OS and CPU.

This does not build or link the rest of BoringSSL. The generated assembly is
already checked in under `boringssl-rob/gen/crypto`; if it needs regeneration,
follow the pre-generated-file instructions in `boringssl-rob/BUILDING.md`.
The build commands below assume the BoringSSL checkout is in the sibling
`boringssl-rob` directory. To use a clone at a different location, add
`-DBORINGSSL_SOURCE_DIR=/path/to/boringssl` to each `cmake -S` configure command.

Build natively on the target OS and architecture. Install prerequisites:

- CMake 3.22 or later and a C++ toolchain.
- NASM for Windows x64.
- Clang's assembler for Windows ARM64, as required by BoringSSL's ARM64
  assembly.

For Windows x64, use Visual Studio 2022 with the x64 C++ build tools and
Windows SDK, plus NASM:

```text
cmake -S current/native -B build/win-x64 -G "Visual Studio 17 2022" -A x64 -DDOTCHACHA_ARCH=x64 -DCMAKE_ASM_NASM_COMPILER=nasm
cmake --build build/win-x64 --config Release
cmake --install build/win-x64 --config Release --prefix current/dotChaCha20/runtimes/win-x64
```

For Linux x64, run on a Linux x64 host with NASM installed:

```text
cmake -S current/native -B build/linux-x64 -DCMAKE_BUILD_TYPE=Release -DDOTCHACHA_ARCH=x64
cmake --build build/linux-x64
cmake --install build/linux-x64 --prefix current/dotChaCha20/runtimes/linux-x64
```

For macOS x64, run on either an Intel or Apple Silicon Mac with Xcode
Command Line Tools and NASM installed. Set `CMAKE_OSX_ARCHITECTURES` to
`x86_64` to cross-compile the x64 binary from an Apple Silicon host. Set
`CMAKE_OSX_DEPLOYMENT_TARGET` to the minimum macOS version the library should
support; this example targets macOS 11.0 and later:

```text
cmake -S current/native -B build/osx-x64 -DCMAKE_BUILD_TYPE=Release -DDOTCHACHA_ARCH=x64 -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
cmake --build build/osx-x64
cmake --install build/osx-x64 --prefix current/dotChaCha20/runtimes/osx-x64
```

For Linux ARM64, run on a Linux ARM64 host:

```text
cmake -S current/native -B build/linux-arm64 -DCMAKE_BUILD_TYPE=Release -DDOTCHACHA_ARCH=arm64
cmake --build build/linux-arm64
cmake --install build/linux-arm64 --prefix current/dotChaCha20/runtimes/linux-arm64
```

For Windows ARM64, use Visual Studio 2022 with the C++ ARM64 build tools, the
ARM64 Windows SDK, and Clang installed. The Visual Studio generator can
cross-compile this target from either an x64 or ARM64 Windows host:

```text
cmake -S current/native -B build/win-arm64 -G "Visual Studio 17 2022" -A ARM64 -DDOTCHACHA_ARCH=arm64 -DCMAKE_ASM_COMPILER=clang -DCMAKE_ASM_COMPILER_TARGET=aarch64-pc-windows-msvc
cmake --build build/win-arm64 --config Release
cmake --install build/win-arm64 --config Release --prefix current/dotChaCha20/runtimes/win-arm64
```

The Visual Studio generator does not compile generic `.S` sources directly, so
the CMake target invokes Clang to assemble BoringSSL's ARM64 source into a
Windows COFF object before linking the DLL.

Install to the matching runtime folder for each native build:

```text
cmake --install TARGET --config Release --prefix current/dotChaCha20/runtimes/RID
```

Use the matching RID:

| OS | Architecture | RID | Assembly entry |
| --- | --- | --- | --- |
| Windows | x64 | `win-x64` | `ChaCha20_ctr32_avx2` |
| Windows | ARM64 | `win-arm64` | `ChaCha20_ctr32_neon` |
| Linux | x64 | `linux-x64` | `ChaCha20_ctr32_avx2` |
| Linux | ARM64 | `linux-arm64` | `ChaCha20_ctr32_neon` |
| macOS | x64 | `osx-x64` | `ChaCha20_ctr32_avx2` |
| macOS | ARM64 | `osx-arm64` | `ChaCha20_ctr32_neon` |

The runtime asset paths are `runtimes/RID/native/chacha20.dll` on Windows,
`runtimes/RID/native/libchacha20.so` on Linux, and
`runtimes/RID/native/libchacha20.dylib` on macOS.

The x64 export intentionally calls the AVX2 assembly entry directly, so the
.NET loader checks AVX2 before loading it. ARM64 uses the NEON entry directly;
NEON is part of the ARM64 baseline. Neither target uses a fake CPU-capability
stub or changes BoringSSL's global CPU detection.
