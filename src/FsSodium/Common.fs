namespace FsSodium

open System.Runtime.InteropServices
open FSharpPlus
open FSharpPlus.Math.Generic

type SodiumError = SodiumError of int

[<RequireQualifiedAccess>]
module Sodium =
    let initialize() =
        match Interop.sodium_init() with
        | 0 | 1 -> Ok ()
        | result -> Error <| SodiumError result

    let getLibsodiumVersion() =
        let intPtr = Interop.sodium_version_string()
        Marshal.PtrToStringAnsi(intPtr)

type Buffers internal (cipherText : byte[], plainText : byte[]) =
    do
        if Array.length cipherText = 0 then invalidArg "cipherText" "cipherText buffer is empty"
        if Array.length plainText = 0 then invalidArg "plainText" "plainText buffer is empty"

    member __.PlainText = plainText
    member __.CipherText = cipherText

type BuffersFactory (macLength) =
    member this.FromPlainText(plainText) =
        let plainTextLength = Array.length plainText
        let cipherText =
            Array.zeroCreate (this.GetCipherTextLength plainTextLength)
        Buffers(cipherText, plainText)
    member this.FromCipherText(cipherText) =
        let cipherTextLength = Array.length cipherText
        let plainText =
            Array.zeroCreate (this.GetPlainTextLength cipherTextLength)
        Buffers(cipherText, plainText)
    member this.FromPlainTextLength(plainTextLength) =
        let plainText = Array.zeroCreate plainTextLength
        let cipherText =
            Array.zeroCreate (this.GetCipherTextLength plainTextLength)
        Buffers(cipherText, plainText)
    member this.FromCipherTextLength(cipherTextLength) =
        let plainText =
            Array.zeroCreate (this.GetPlainTextLength cipherTextLength)
        let cipherText = Array.zeroCreate cipherTextLength
        Buffers(cipherText, plainText)
    member __.GetCipherTextLength plainTextLength =
        if plainTextLength <= 0 then 0 else plainTextLength + macLength
    member __.GetPlainTextLength cipherTextLength =
        if cipherTextLength <= macLength
        then 0
        else cipherTextLength - macLength
