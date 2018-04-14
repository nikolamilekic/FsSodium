module FsSodium.Interop

open System.Runtime.InteropServices

[<DllImport(@"libsodium", CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_init()
