module FsSodium.SecretKeyEncryption

open System.Security.Cryptography
open Chessie.ErrorHandling
open FsSodium

let private keyLength = Interop.crypto_secretbox_keybytes()
let private nonceLength = Interop.crypto_secretbox_noncebytes()
let private macLength = Interop.crypto_secretbox_macbytes()

type Key private (key) =
    inherit Secret(key)
    static member GenerateDisposable() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretbox_keygen(key.Secret)
        key
    static member FromPasswordDisposable(parameters, password) =
        trial {
            let! keyLength = PasswordHashing.KeyLength.Create keyLength
            let! key = PasswordHashing.hashPassword keyLength parameters password
            return new Key(key)
        }
        |> Trial.returnOrFail
type Nonce = private Nonce of byte[]
    with static member Generate() = Random.bytes nonceLength |> Nonce
let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength
let encryptTo (key : Key) (Nonce nonce) plainText plainTextLength cipherText =
    if Array.length cipherText < getCipherTextLength plainTextLength
    then failwith "Cipher text buffer is not big enough." else

    if Array.length plainText < plainTextLength
    then failwith "Plain text was expected to be larger." else

    let result =
        Interop.crypto_secretbox_easy(
            cipherText,
            plainText,
            int64 plainTextLength,
            nonce,
            key.Secret)

    if result <> 0 then
        CryptographicException("Encryption failed. This should not happen. Please report this error.")
        |> raise
let encrypt key nonce plainText =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    encryptTo key nonce plainText plainTextLength cipherText
    cipherText
let decryptTo
    (key : Key)
    (Nonce nonce)
    cipherText
    cipherTextLength
    plainText  =

    if Array.length plainText < getPlainTextLength cipherTextLength
    then failwith "Plain text buffer is not big enough." else

    if Array.length cipherText < cipherTextLength
    then failwith "Cipher text was expected to be larger." else

    let result =
        Interop.crypto_secretbox_open_easy(
            plainText,
            cipherText,
            int64 cipherTextLength,
            nonce,
            key.Secret)

    if result = 0 then ok () else fail "Decryption failed."
let decrypt key nonce cipherText = trial {
    let cipherTextLength = Array.length cipherText
    let plainTextLength = getPlainTextLength cipherTextLength
    let plainText = Array.zeroCreate plainTextLength
    do! decryptTo key nonce cipherText cipherTextLength plainText
    return plainText
}
