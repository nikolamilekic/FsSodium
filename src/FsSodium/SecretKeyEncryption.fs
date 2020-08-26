module FsSodium.SecretKeyEncryption

open FsSodium
open Milekic.YoLo
open Milekic.YoLo.Validation
open Milekic.YoLo.Result.Operators

let private keyLength = Interop.crypto_secretbox_keybytes() |> capToInt
let private passwordHashingKeyLength =
    PasswordHashing.KeyLength.Validate keyLength
    |> Result.failOnError "Key length is not supported."
let private nonceLength = Interop.crypto_secretbox_noncebytes() |> capToInt
let private macLength = Interop.crypto_secretbox_macbytes() |> capToInt
type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretbox_keygen(key.Secret)
        key
    static member FromPassword(parameters, password) =
        PasswordHashing.hashPassword passwordHashingKeyLength parameters password
        |> Result.map (fun x -> new Key(x))
    static member Length = keyLength
    static member Validate x =
        validateArrayLength keyLength (fun x -> new Key(x)) x
type Nonce =
    private | Nonce of byte[]
    member this.Value = let (Nonce x) = this in x
    static member Generate() = Random.bytes nonceLength |> Nonce
    static member Validate x = validateArrayLength nonceLength Nonce x
    static member Length = nonceLength
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
