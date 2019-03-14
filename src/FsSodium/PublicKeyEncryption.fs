module FsSodium.PublicKeyEncryption

open System
open Milekic.YoLo

let private publicKeyLength = Interop.crypto_box_publickeybytes()
let private secretKeyLength = Interop.crypto_box_secretkeybytes()
let private nonceLength = Interop.crypto_box_noncebytes()
let private macLength = Interop.crypto_box_macbytes()

type PublicKey = private PublicKey of byte[]
type KeyGenerationError = SodiumError of int
type SecretKey private (secretKey, publicKey) =
    inherit Secret(secretKey)
    member __.PublicKey = publicKey
    static member GenerateDisposable() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let secret = new SecretKey(secretKey, PublicKey publicKey)
        let result = Interop.crypto_box_keypair(publicKey, secretKey)
        if result = 0 then Ok secret
        else (secret :> IDisposable).Dispose(); Error <| SodiumError result

type Nonce = private Nonce of byte[]
    with static member Generate() = Random.bytes nonceLength |> Nonce

let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength

type EncryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let encryptTo
    (senderKey : SecretKey)
    (PublicKey recipientKey)
    (Nonce nonce)
    plainText
    plainTextLength
    cipherText =

    if Array.length cipherText < getCipherTextLength plainTextLength
    then Error CipherTextBufferIsNotBigEnough else

    if Array.length plainText < plainTextLength
    then Error PlainTextBufferIsNotBigEnough else

    let result =
        Interop.crypto_box_easy(
            cipherText,
            plainText,
            uint64 plainTextLength,
            nonce,
            recipientKey,
            senderKey.Secret)

    if result = 0 then Ok () else Error <| SodiumError result
let encrypt sender recipient nonce plainText =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    encryptTo sender recipient nonce plainText plainTextLength cipherText
    >>-. cipherText

type DecryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let decryptTo
    (recipientKey : SecretKey)
    (PublicKey senderKey)
    (Nonce nonce)
    cipherText
    cipherTextLength
    plainText =

    if Array.length plainText < getPlainTextLength cipherTextLength
    then Error PlainTextBufferIsNotBigEnough else

    if Array.length cipherText < cipherTextLength
    then Error CipherTextBufferIsNotBigEnough else

    let result =
        Interop.crypto_box_open_easy(
            plainText,
            cipherText,
            uint64 cipherTextLength,
            nonce,
            senderKey,
            recipientKey.Secret)

    if result = 0 then Ok () else Error <| SodiumError result
let decrypt recipientKey senderKey nonce cipherText = result {
    let cipherTextLength = Array.length cipherText
    let plainTextLength = getPlainTextLength cipherTextLength
    let plainText = Array.zeroCreate plainTextLength
    do!
        decryptTo
            recipientKey
            senderKey
            nonce
            cipherText
            cipherTextLength
            plainText
    return plainText
}
