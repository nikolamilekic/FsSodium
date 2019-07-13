module FsSodium.PublicKeyEncryption

open System
open Milekic.YoLo
open Milekic.YoLo.Result.Operators

let private publicKeyLength = Interop.crypto_box_publickeybytes()
let private secretKeyLength = Interop.crypto_box_secretkeybytes()
let private nonceLength = Interop.crypto_box_noncebytes()
let private macLength = Interop.crypto_box_macbytes()

type PublicKeyValidationError = KeyBufferIsOfWrongLength
type PublicKeyComputationError =
    | SecretKeyIsOfWrongLength
    | SodiumError of int
type PublicKey = private PublicKey of byte[]
    with
        member this.Bytes = let (PublicKey x) = this in x
        static member Length = publicKeyLength
        static member Validate x =
            if Array.length x = publicKeyLength
            then Ok <| PublicKey x
            else Error KeyBufferIsOfWrongLength
        static member Compute secretKey =
            if Array.length secretKey <> secretKeyLength
            then Error PublicKeyComputationError.SecretKeyIsOfWrongLength
            else
            let publicKey = Array.zeroCreate publicKeyLength
            let result = Interop.crypto_scalarmult_base(publicKey, secretKey)
            if result = 0 then Ok <| PublicKey publicKey
            else Error <| SodiumError result

type KeyGenerationError = SodiumError of int
type SecretKeyValidationError =
    | SecretKeyIsOfWrongLength
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
    static member Length = secretKeyLength
    static member ValidateDisposable (secretKey, publicKey) =
        if Array.length secretKey <> secretKeyLength
        then Error SecretKeyIsOfWrongLength
        else Ok <| new SecretKey(secretKey, publicKey)

type NonceValidationError = NonceBufferIfOfWrongLength
type Nonce = private Nonce of byte[]
    with
        member this.Bytes = let (Nonce x) = this in x
        static member Generate() = Random.bytes nonceLength |> Nonce
        static member Validate x =
            if Array.length x = nonceLength
            then Ok <| Nonce x
            else Error NonceBufferIfOfWrongLength
        static member Length = nonceLength

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
