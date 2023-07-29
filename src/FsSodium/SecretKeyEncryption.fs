[<RequireQualifiedAccess>]
module FsSodium.SecretKeyEncryption

open FSharpPlus

let private keyLength = lazy (Interop.crypto_secretbox_keybytes() |> int)
let private nonceLength = lazy (Interop.crypto_secretbox_noncebytes() |> int)
let private macLength = lazy (Interop.crypto_secretbox_macbytes() |> int |> MacLength)
let getCipherTextLength plainTextLength = Sodium.getCipherTextLength macLength.Value plainTextLength
let getPlainTextLength cipherTextLength = Sodium.getPlainTextLength macLength.Value cipherTextLength

type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        Sodium.initialize ()
        let key = new Key(Array.zeroCreate keyLength.Value)
        Interop.crypto_secretbox_keygen(key.Get)
        key
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> keyLength.Value then Error () else Ok <| new Key(x)
type Nonce = private | Nonce of byte[] with
    member this.Get = let (Nonce x) = this in x
    static member Generate() =
        Sodium.initialize ()
        Random.bytes nonceLength.Value |> Nonce
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> nonceLength.Value then Error () else Ok <| Nonce x

let encryptTo (key : Key) (Nonce nonce) (PlainText plainText) (CipherText cipherText) plainTextLength =
    Sodium.initialize ()

    if Array.length plainText < plainTextLength then
        invalidArg "plainTextLength" "Provided plain text buffer is too small"
    if Array.length cipherText < getCipherTextLength plainTextLength then
        invalidArg "cipherText" "Provided cipher text buffer is too small"

    let result =
        Interop.crypto_secretbox_easy(
            cipherText,
            plainText,
            uint64 plainTextLength,
            nonce,
            key.Get)

    if result = 0 then Ok () else Error <| SodiumError result
let encrypt key nonce plainText =
    let plainTextLength = Array.length plainText
    let cipherText = Array.zeroCreate <| getCipherTextLength plainTextLength
    encryptTo key nonce (PlainText plainText) (CipherText cipherText) plainTextLength
    |>> konst cipherText

let decryptTo (key : Key) (Nonce nonce) (CipherText cipherText) (PlainText plainText) cipherTextLength =
    Sodium.initialize ()

    if Array.length cipherText < cipherTextLength then
        invalidArg "cipherTextLength" "Provided cipher text buffer too small"
    if Array.length plainText < getPlainTextLength cipherTextLength then
        invalidArg "plainText" "Provided plain text buffer is too small"

    let result =
        Interop.crypto_secretbox_open_easy(
            plainText,
            cipherText,
            uint64 cipherTextLength,
            nonce,
            key.Get)

    if result = 0 then Ok () else Error <| SodiumError result
let decrypt key nonce cipherText =
    let cipherTextLength = Array.length cipherText
    let plainText = Array.zeroCreate <| getPlainTextLength cipherTextLength
    decryptTo key nonce (CipherText cipherText) (PlainText plainText) cipherTextLength
    |>> konst plainText
