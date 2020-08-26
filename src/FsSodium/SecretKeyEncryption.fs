namespace FsSodium.SecretKeyEncryption

open FSharpPlus

open FsSodium
open Buffers

module internal AlgorithmInfo =
    let keyLength = Interop.crypto_secretbox_keybytes() |> int
    let nonceLength = Interop.crypto_secretbox_noncebytes() |> int
    let macLength = Interop.crypto_secretbox_macbytes() |> int

open AlgorithmInfo

type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretbox_keygen(key.Get)
        key
    static member Import x =
        if Array.length x <> keyLength then Error () else Ok <| new Key(x)
type Nonce = private | Nonce of byte[] with
    member this.Get = let (Nonce x) = this in x
    static member Generate() = Random.bytes nonceLength |> Nonce
    static member Import x =
        if Array.length x <> nonceLength then Error () else Ok <| Nonce x

[<RequireQualifiedAccess>]
module SecretKeyEncryption =
    let buffersFactory = BuffersFactory(macLength)
    let encryptTo (key : Key) (buffers : Buffers) (Nonce nonce) plainTextLength =
        let plainText = buffers.PlainText
        if Array.length plainText < plainTextLength then
            invalidArg "plainTextLength" "Provided plain text buffer is too small"

        let result =
            Interop.crypto_secretbox_easy(
                buffers.CipherText,
                plainText,
                uint64 plainTextLength,
                nonce,
                key.Get)

        if result = 0 then Ok () else Error <| SodiumError result
    let encrypt key (nonce, plainText) =
        let buffers = buffersFactory.FromPlainText plainText
        let plainTextLength = Array.length plainText
        encryptTo key buffers nonce plainTextLength
        |>> konst buffers.CipherText

    let decryptTo (key : Key) (buffers : Buffers) (Nonce nonce) cipherTextLength =
        let cipherText = buffers.CipherText
        if Array.length cipherText < cipherTextLength then
            invalidArg "cipherTextLength" "Provided cipher text buffer too small"

        let result =
            Interop.crypto_secretbox_open_easy(
                buffers.PlainText,
                cipherText,
                uint64 cipherTextLength,
                nonce,
                key.Get)

        if result = 0 then Ok () else Error <| SodiumError result
    let decrypt key (nonce, cipherText) =
        let buffers = buffersFactory.FromCipherText cipherText
        let cipherTextLength = Array.length cipherText
        decryptTo key buffers nonce cipherTextLength
        |>> konst buffers.PlainText
