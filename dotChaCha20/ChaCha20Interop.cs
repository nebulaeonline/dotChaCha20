using System.Runtime.InteropServices;

namespace nebulae.dotChaCha20
{
    public static class ChaCha20Interop
    {
        // Safe byte[]-based version
        [DllImport("chacha20", CallingConvention = CallingConvention.Cdecl)]
        public static extern int chacha20_encrypt(
            byte[] key,     // 32 bytes
            byte[] nonce,   // 12 bytes
            uint counter,
            byte[] input,
            byte[] output,
            UIntPtr length);

        // Unsafe pointer-based version (high performance, no GC pinning)
        [DllImport("chacha20", EntryPoint = "chacha20_encrypt", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int chacha20_encrypt_ptr(
            byte* key,
            byte* nonce,
            uint counter,
            byte* input,
            byte* output,
            UIntPtr length);
    }
}
