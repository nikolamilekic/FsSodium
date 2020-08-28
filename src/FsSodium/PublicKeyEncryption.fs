[<RequireQualifiedAccess>]
module FsSodium.PublicKeyEncryption

open Milekic.YoLo
open FSharpPlus

let private publicKeyLength = lazy (Interop.crypto_box_publickeybytes() |> int)
let private secretKeyLength = lazy (Interop.crypto_box_secretkeybytes() |> int)
let private nonceLength = lazy (Interop.crypto_box_noncebytes() |> int)
let private macLength = lazy (Interop.crypto_box_macbytes() |> int)
let private sharedSecretLength = lazy (Interop.crypto_box_beforenmbytes() |> int)

type SecretKey private (secretKey) =
    inherit Secret(secretKey)
    static member Generate() =
        Sodium.initialize ()
        let publicKey = Array.zeroCreate publicKeyLength.Value
        let secretKey = Array.zeroCreate secretKeyLength.Value
        let result = Interop.crypto_box_keypair(publicKey, secretKey)
        if result = 0 then Ok <| (new SecretKey(secretKey), PublicKey publicKey)
        else Error <| SodiumError result
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> secretKeyLength.Value
        then Error ()
        else Ok <| new SecretKey(x)
and PublicKey = private | PublicKey of byte[] with
    member this.Get = let (PublicKey x) = this in x
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> publicKeyLength.Value
        then Error ()
        else Ok <| PublicKey x
    static member FromSecretKey (secretKey : SecretKey) =
        Sodium.initialize ()
        let publicKey = Array.zeroCreate publicKeyLength.Value
        let result = Interop.crypto_scalarmult_base(publicKey, secretKey.Get)
        if result = 0 then Ok <| PublicKey publicKey
        else Error <| SodiumError result
and SharedSecret (sharedSecret) =
    inherit Secret(sharedSecret)
    static member Precompute (secretKey : SecretKey) (publicKey : PublicKey) =
        Sodium.initialize ()
        let sharedSecret = Array.zeroCreate sharedSecretLength.Value
        let result =
            Interop.crypto_box_beforenm(
                sharedSecret, publicKey.Get, secretKey.Get)

        if result = 0
        then Ok <| new SharedSecret(sharedSecret)
        else Error <| SodiumError result
type Nonce = private | Nonce of byte[] with
    member this.Get = let (Nonce x) = this in x
    static member Generate() =
        Sodium.initialize ()
        Random.bytes nonceLength.Value |> Nonce
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> nonceLength.Value then Error () else Ok <| Nonce x

let makeBuffersFactory () =
    Sodium.initialize ()
    BuffersFactory(macLength.Value)
let encryptTo
    (senderKey : SecretKey)
    (PublicKey recipientKey)
    (buffers : Buffers)
    (Nonce nonce)
    plainTextLength =

    Sodium.initialize ()

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
let encrypt senderKey recipientKey nonce plainText =
    let buffersFactory = makeBuffersFactory ()
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

    Sodium.initialize ()

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
let decrypt recipientKey senderKey nonce cipherText =
    Sodium.initialize ()
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromCipherText cipherText
    let cipherTextLength = Array.length cipherText
    decryptTo recipientKey senderKey buffers nonce cipherTextLength
    |>> konst buffers.PlainText
let encryptWithSharedSecretTo
    (sharedSecret : SharedSecret)
    (buffers : Buffers)
    (Nonce nonce)
    plainTextLength =

    Sodium.initialize ()

    let plainText = buffers.PlainText
    if Array.length plainText < plainTextLength then
        invalidArg "plainTextLength" "Provided plain text buffer too small"

    let result =
        Interop.crypto_box_easy_afternm(
            buffers.CipherText,
            plainText,
            uint64 plainTextLength,
            nonce,
            sharedSecret.Get)

    if result = 0 then Ok () else Error <| SodiumError result
let encryptWithSharedSecret sharedSecret nonce plainText =
    Sodium.initialize ()
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromPlainText plainText
    let plainTextLength = Array.length plainText
    encryptWithSharedSecretTo sharedSecret buffers nonce plainTextLength
    |>> konst buffers.CipherText
let decryptWithSharedSecretTo
    (sharedSecret : SharedSecret)
    (buffers : Buffers)
    (Nonce nonce)
    cipherTextLength =

    Sodium.initialize ()

    let cipherText = buffers.CipherText
    if Array.length cipherText < cipherTextLength then
        invalidArg "cipherTextLength" "Provided cipher text buffer too small"

    let result =
        Interop.crypto_box_open_easy_afternm(
            buffers.PlainText,
            cipherText,
            uint64 cipherTextLength,
            nonce,
            sharedSecret.Get)

    if result = 0 then Ok () else Error <| SodiumError result
let decryptWithSharedSecret sharedSecret nonce cipherText =
    Sodium.initialize ()
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromCipherText cipherText
    let cipherTextLength = Array.length cipherText
    decryptWithSharedSecretTo sharedSecret buffers nonce cipherTextLength
    |>> konst buffers.PlainText
