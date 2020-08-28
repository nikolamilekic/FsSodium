namespace FsSodium.PublicKeyEncryption

open System
open Milekic.YoLo
open FSharpPlus

open FsSodium
open FsSodium.Buffers

module internal AlgorithmInfo =
    let publicKeyLength = Interop.crypto_box_publickeybytes() |> int
    let secretKeyLength = Interop.crypto_box_secretkeybytes() |> int
    let nonceLength = Interop.crypto_box_noncebytes() |> int
    let macLength = Interop.crypto_box_macbytes() |> int
    let sharedKeyLength = Interop.crypto_box_beforenmbytes() |> int

open AlgorithmInfo

type SecretKey private (secretKey) =
    inherit Secret(secretKey)
    static member Generate() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let result = Interop.crypto_box_keypair(publicKey, secretKey)
        if result = 0 then Ok <| (new SecretKey(secretKey), PublicKey publicKey)
        else Error <| SodiumError result
    static member Import x =
        if Array.length x <> secretKeyLength
        then Error ()
        else Ok <| new SecretKey(x)
and PublicKey = private | PublicKey of byte[] with
    member this.Get = let (PublicKey x) = this in x
    static member Import x =
        if Array.length x <> publicKeyLength then Error () else Ok <| PublicKey x
    static member FromSecretKey (secretKey : SecretKey) =
        let publicKey = Array.zeroCreate publicKeyLength
        let result = Interop.crypto_scalarmult_base(publicKey, secretKey.Get)
        if result = 0 then Ok <| PublicKey publicKey
        else Error <| SodiumError result
and SharedKey (sharedKey) =
    inherit Secret(sharedKey)
    static member Import x =
        if Array.length x <> sharedKeyLength
        then Error ()
        else Ok <| new SharedKey(x)
type Nonce = private | Nonce of byte[] with
    member this.Get = let (Nonce x) = this in x
    static member Generate() = Random.bytes nonceLength |> Nonce
    static member Import x =
        if Array.length x <> nonceLength then Error () else Ok <| Nonce x

[<RequireQualifiedAccess>]
module PublicKeyEncryption =
    let buffersFactory = BuffersFactory(macLength)

    let encryptTo
        (senderKey : SecretKey)
        (PublicKey recipientKey)
        (buffers : Buffers)
        (Nonce nonce)
        plainTextLength =

        let plainText = buffers.PlainText
        if Array.length plainText < plainTextLength then
            invalidArg "plainTextLength" "Provided plain text buffer is too small"

        let result =
            Interop.crypto_box_easy(
                buffers.CipherText,
                plainText,
                uint64 plainTextLength,
                nonce,
                recipientKey,
                senderKey.Get)

        if result = 0 then Ok () else Error <| SodiumError result
    let encrypt senderKey recipientKey (nonce, plainText) =
        let buffers = buffersFactory.FromPlainText plainText
        let plainTextLength = Array.length plainText
        encryptTo senderKey recipientKey buffers nonce plainTextLength
        |>> konst buffers.CipherText

    let decryptTo
        (recipientKey : SecretKey)
        (PublicKey senderKey)
        (buffers : Buffers)
        (Nonce nonce)
        cipherTextLength =

        let cipherText = buffers.CipherText
        if Array.length cipherText < cipherTextLength then
            invalidArg "cipherTextLength" "Provided cipher text buffer too small"

        let result =
            Interop.crypto_box_open_easy(
                buffers.PlainText,
                cipherText,
                uint64 cipherTextLength,
                nonce,
                senderKey,
                recipientKey.Get)

        if result = 0 then Ok () else Error <| SodiumError result
    let decrypt recipientKey senderKey (nonce, cipherText) =
        let buffers = buffersFactory.FromCipherText cipherText
        let cipherTextLength = Array.length cipherText
        decryptTo recipientKey senderKey buffers nonce cipherTextLength
        |>> konst buffers.PlainText

    let precomputeSharedKey (recipientKey : SecretKey) (PublicKey senderKey) =
        let sharedKeyBuffer = Array.zeroCreate sharedKeyLength
        let sharedKey =
            SharedKey.Import sharedKeyBuffer
            |> Result.failOnError "Could not import shared key"

        let result =
            Interop.crypto_box_beforenm(
                sharedKeyBuffer, senderKey, recipientKey.Get)

        if result = 0 then Ok sharedKey else Error <| SodiumError result
    let encryptWithSharedKeyTo
        (key : SharedKey)
        (buffers : Buffers)
        (Nonce nonce)
        plainTextLength =

        let plainText = buffers.PlainText
        if Array.length plainText < plainTextLength then
            invalidArg "plainTextLength" "Provided plain text buffer too small"

        let result =
            Interop.crypto_box_easy_afternm(
                buffers.CipherText,
                plainText,
                uint64 plainTextLength,
                nonce,
                key.Get)

        if result = 0 then Ok () else Error <| SodiumError result
    let encryptWithSharedKey sharedKey (nonce, plainText) =
        let buffers = buffersFactory.FromPlainText plainText
        let plainTextLength = Array.length plainText
        encryptWithSharedKeyTo sharedKey buffers nonce plainTextLength
        |>> konst buffers.CipherText
    let decryptWithSharedKeyTo
        (key : SharedKey)
        (buffers : Buffers)
        (Nonce nonce)
        cipherTextLength =

        let cipherText = buffers.CipherText
        if Array.length cipherText < cipherTextLength then
            invalidArg "cipherTextLength" "Provided cipher text buffer too small"

        let result =
            Interop.crypto_box_open_easy_afternm(
                buffers.PlainText,
                cipherText,
                uint64 cipherTextLength,
                nonce,
                key.Get)

        if result = 0 then Ok () else Error <| SodiumError result
    let decryptWithSharedKey sharedKey (nonce, cipherText) =
        let buffers = buffersFactory.FromCipherText cipherText
        let cipherTextLength = Array.length cipherText
        decryptWithSharedKeyTo sharedKey buffers nonce cipherTextLength
        |>> konst buffers.PlainText
