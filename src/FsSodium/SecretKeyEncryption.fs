module FsSodium.SecretKeyEncryption

open FsSodium
open Milekic.YoLo

let private keyLength = Interop.crypto_secretbox_keybytes()
let private nonceLength = Interop.crypto_secretbox_noncebytes()
let private macLength = Interop.crypto_secretbox_macbytes()
type KeyGenerationFromPasswordError =
    | WrongKeyLength of ValidateRangeError
    | HashPasswordError of PasswordHashing.HashPasswordError
type Key private (key) =
    inherit Secret(key)
    static member GenerateDisposable() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretbox_keygen(key.Secret)
        key
    static member FromPasswordDisposable(parameters, password) = result {
        let! keyLength =
            PasswordHashing.KeyLength.Create keyLength >>-! WrongKeyLength
        let! key =
            PasswordHashing.hashPassword keyLength parameters password
            >>-! HashPasswordError
        return new Key(key)
    }
type Nonce = private Nonce of byte[]
    with static member Generate() = Random.bytes nonceLength |> Nonce
let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength

type EncryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let encryptTo (key : Key) (Nonce nonce) plainText plainTextLength cipherText =
    if Array.length cipherText < getCipherTextLength plainTextLength
    then Error CipherTextBufferIsNotBigEnough else

    if Array.length plainText < plainTextLength
    then Error PlainTextBufferIsNotBigEnough else

    let result =
        Interop.crypto_secretbox_easy(
            cipherText,
            plainText,
            uint64 plainTextLength,
            nonce,
            key.Secret)

    if result = 0 then Ok () else Error <| SodiumError result
let encrypt key nonce plainText =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    encryptTo key nonce plainText plainTextLength cipherText >>-. cipherText

type DecryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let decryptTo
    (key : Key)
    (Nonce nonce)
    cipherText
    cipherTextLength
    plainText  =

    if Array.length plainText < getPlainTextLength cipherTextLength
    then Error PlainTextBufferIsNotBigEnough else

    if Array.length cipherText < cipherTextLength
    then Error CipherTextBufferIsNotBigEnough else

    let result =
        Interop.crypto_secretbox_open_easy(
            plainText,
            cipherText,
            uint64 cipherTextLength,
            nonce,
            key.Secret)

    if result = 0 then Ok () else Error <| SodiumError result
let decrypt key nonce cipherText = result {
    let cipherTextLength = Array.length cipherText
    let plainTextLength = getPlainTextLength cipherTextLength
    let plainText = Array.zeroCreate plainTextLength
    do! decryptTo key nonce cipherText cipherTextLength plainText
    return plainText
}
