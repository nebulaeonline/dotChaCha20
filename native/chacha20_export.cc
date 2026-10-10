// chacha20_export.cc
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
  #define EXPORT __declspec(dllexport)
#else
  #define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

#if defined(CHACHA20_NATIVE_AVX2)
void ChaCha20_ctr32_avx2(uint8_t *out, const uint8_t *in, size_t len,
                         const uint32_t key[8], const uint32_t counter[4]);
#elif defined(CHACHA20_NATIVE_NEON)
void ChaCha20_ctr32_neon(uint8_t *out, const uint8_t *in, size_t len,
                         const uint32_t key[8], const uint32_t counter[4]);
#else
#error "Define exactly one supported ChaCha20 native implementation"
#endif

EXPORT int chacha20_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    if (length == 0)
        return 0;

    uint32_t key_words[8];
    uint32_t counter_words[4];

    memcpy(key_words, key, 32);
    counter_words[0] = counter;
    memcpy(&counter_words[1], nonce, 12);

#if defined(CHACHA20_NATIVE_AVX2)
    ChaCha20_ctr32_avx2(output, input, length, key_words, counter_words);
#else
    ChaCha20_ctr32_neon(output, input, length, key_words, counter_words);
#endif
    return 0;
}
}
