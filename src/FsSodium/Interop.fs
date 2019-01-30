module internal FsSodium.Interop

open System
open System.Runtime.InteropServices

[<Literal>]
let Name = "libsodium"

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_init()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign(
    byte[] signedText,
    IntPtr signedTextLength,
    byte[] plainText,
    int64 plainTextLength,
    byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_open(
    byte[] plainText,
    IntPtr plainTextLength,
    byte[] signedText,
    int64 signedTextLength,
    byte[] publicKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_easy(
    byte[] cipherText,
    byte[] plainText,
    int64 plainTextLength,
    byte[] nonce,
    byte[] publicKey,
    byte[] secretKey);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_open_easy(
    byte[] plainText,
    byte[] cipherText,
    int64 cipherTextLength,
    byte[] nonce,
    byte[] publicKey,
    byte[] secretKey);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_keypair(byte[] publicKey, byte[] secretKey);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern void randombytes_buf(byte[] buffer, int64 bufferSize);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_mlock(
    byte[] array,
    int length);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_munlock(
    byte[] array,
    int length);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern void sodium_memzero(
    byte[] array,
    int length);
