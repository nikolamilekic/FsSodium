module FsSodium.SecretKeyEncryption

open System.Security.Cryptography

type Key = private KeySecret of Secret
type Nonce = private NonceBytes of byte[]
type CipherText = { CipherTextBytes : byte[]; Nonce : Nonce }

let private keyLength = 32;
let private nonceLength = 24;
let private macLength = 16;

let encrypt
    (KeySecret key)
    ((NonceBytes nonceBytes) as nonce, (PlainTextBytes plainText)) =

    let plainTextLength = Array.length plainText
    let cipherTextLength = macLength + plainTextLength
    let cipherText = Array.zeroCreate cipherTextLength

    let result =
        Interop.crypto_secretbox_easy(
            cipherText,
            plainText,
            int64 plainTextLength,
            nonceBytes,
            key.Secret)

    if result = 0
    then { CipherTextBytes = cipherText; Nonce = nonce }
    else CryptographicException("Encryption failed. This should not happen. Please report this error.")
         |> raise
let decrypt
    (KeySecret key)
    { CipherTextBytes = cipherText; Nonce = NonceBytes nonce } =

    let cipherTextLength = Array.length cipherText
    let plainTextLength = cipherTextLength - macLength
    let plainText = Array.zeroCreate plainTextLength

    let result =
        Interop.crypto_secretbox_open_easy(
            plainText,
            cipherText,
            int64 cipherTextLength,
            nonce,
            key.Secret)

    if result = 0 then Ok <| PlainTextBytes plainText else Error()
let generateKey() =
    let key = Array.zeroCreate keyLength
    let secret = new Secret(key)
    Interop.crypto_secretbox_keygen(key)
    KeySecret secret
let generateNonce() = Random.bytes nonceLength |> NonceBytes