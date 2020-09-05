[<RequireQualifiedAccess>]
module FsSodium.SecretKeyEncryption

open FSharpPlus

let private keyLength = lazy (Interop.crypto_secretbox_keybytes() |> int)
let private nonceLength = lazy (Interop.crypto_secretbox_noncebytes() |> int)
let private macLength = lazy (Interop.crypto_secretbox_macbytes() |> int)

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

let makeBuffersFactory () =
    Sodium.initialize ()
    BuffersFactory(macLength.Value)
let encryptTo (key : Key) (Nonce nonce) (buffers : Buffers) plainTextLength =
    Sodium.initialize ()
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
let encrypt key nonce plainText =
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromPlainText plainText
    let plainTextLength = Array.length plainText
    encryptTo key nonce buffers plainTextLength
    |>> konst buffers.CipherText

let decryptTo (key : Key) (Nonce nonce) (buffers : Buffers) cipherTextLength =
    Sodium.initialize ()
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
let decrypt key nonce cipherText =
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromCipherText cipherText
    let cipherTextLength = Array.length cipherText
    decryptTo key nonce buffers cipherTextLength
    |>> konst buffers.PlainText
