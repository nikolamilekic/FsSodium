module internal FsSodium.Interop

open System
open System.Runtime.InteropServices

[<Literal>]
let Name = "libsodium"

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_init()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_publickeybytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_secretkeybytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_bytes();

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
extern int crypto_box_publickeybytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_secretkeybytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_macbytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_noncebytes();

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

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_pwhash_alg_default();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_pwhash_saltbytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_pwhash(
    byte[] key,
    int64 keyLength,
    byte[] password,
    int64 passwordLength,
    byte[] salt,
    int64 maxNumberOfOperations,
    int maxAmountOfMemoryToUse,
    int algorithm);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_keybytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_macbytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_noncebytes();

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_easy(
    byte[] cipherText,
    byte[] plainText,
    int64 plainTextLength,
    byte[] nonce,
    byte[] key);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_open_easy(
    byte[] plainText,
    byte[] cipherText,
    int64 cipherTextLength,
    byte[] nonce,
    byte[] key);

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern void crypto_secretbox_keygen(byte[] key);
