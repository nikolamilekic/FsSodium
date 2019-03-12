module FsSodium.PublicKeyEncryption

open System
open System.Security.Cryptography
open Milekic.YoLo

let private publicKeyLength = Interop.crypto_box_publickeybytes()
let private secretKeyLength = Interop.crypto_box_secretkeybytes()
let private nonceLength = Interop.crypto_box_noncebytes()
let private macLength = Interop.crypto_box_macbytes()

type PublicKey = private PublicKey of byte[]
type SecretKey private (secretKey, publicKey) =
    inherit Secret(secretKey)
    member __.PublicKey = publicKey
    static member GenerateDisposable() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let secret = new SecretKey(secretKey, PublicKey publicKey)
        let result = Interop.crypto_box_keypair(publicKey, secretKey)
        if result = 0 then secret
        else
            (secret :> IDisposable).Dispose()
            CryptographicException("Encryption key generation failed. This should not happen. Please report this error.")
            |> raise

type Nonce = private Nonce of byte[]
    with static member Generate() = Random.bytes nonceLength |> Nonce

let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength

let encryptTo
    (senderKey : SecretKey)
    (PublicKey recipientKey)
    (Nonce nonce)
    plainText
    plainTextLength
    cipherText =

    if Array.length cipherText < getCipherTextLength plainTextLength
    then failwith "Cipher text buffer is not big enough." else

    if Array.length plainText < plainTextLength
    then failwith "Plain text was expected to be larger." else

    let result =
        Interop.crypto_box_easy(
            cipherText,
            plainText,
            int64 plainTextLength,
            nonce,
            recipientKey,
            senderKey.Secret)

    if result <> 0 then
        CryptographicException("Encryption failed. This should not happen. Please report this error.")
        |> raise
let encrypt sender recipient nonce plainText =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    encryptTo sender recipient nonce plainText plainTextLength cipherText
    cipherText

let decryptTo
    (recipientKey : SecretKey)
    (PublicKey senderKey)
    (Nonce nonce)
    cipherText
    cipherTextLength
    plainText =

    if Array.length plainText < getPlainTextLength cipherTextLength
    then failwith "Plain text buffer is not big enough." else

    if Array.length cipherText < cipherTextLength
    then failwith "Cipher text was expected to be larger." else

    let result =
        Interop.crypto_box_open_easy(
            plainText,
            cipherText,
            int64 cipherTextLength,
            nonce,
            senderKey,
            recipientKey.Secret)

    if result = 0 then Ok () else Error "Decryption failed."
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
