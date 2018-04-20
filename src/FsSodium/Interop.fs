module FsSodium.Interop

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
