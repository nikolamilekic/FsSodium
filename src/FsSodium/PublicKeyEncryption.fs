module FsSodium.PublicKeyEncryption

open System
open System.Security.Cryptography

type SecretKey = private SecretKeySecret of Secret
type PublicKey = private PublicKeyBytes of byte[]
type Nonce = private NonceBytes of byte[]
type CipherText = { CipherTextBytes : byte[]; Nonce : Nonce }

let private publicKeyLength = Interop.crypto_box_publickeybytes()
let private secretKeyLength = Interop.crypto_box_secretkeybytes()
let private nonceLength = Interop.crypto_box_noncebytes()
let private macLength = Interop.crypto_box_macbytes()

let encrypt
    (SecretKeySecret senderKey)
    (PublicKeyBytes recipientKey)
    ((NonceBytes nonceBytes) as nonce, (PlainText plainText)) =

    let plainTextLength = Array.length plainText
    let cipherTextLength = macLength + plainTextLength
    let cipherText = Array.zeroCreate cipherTextLength

    let result =
        Interop.crypto_box_easy(
            cipherText,
            plainText,
            int64 plainTextLength,
            nonceBytes,
            recipientKey,
            senderKey.Secret)

    if result = 0
    then { CipherTextBytes = cipherText; Nonce = nonce }
    else CryptographicException("Encryption failed. This should not happen. Please report this error.")
         |> raise
let decrypt
    (SecretKeySecret recipientKey)
    (PublicKeyBytes senderKey)
    { CipherTextBytes = cipherText; Nonce = NonceBytes nonce } =

    let cipherTextLength = Array.length cipherText
    let plainTextLength = cipherTextLength - macLength
    let plainText = Array.zeroCreate plainTextLength

    let result =
        Interop.crypto_box_open_easy(
            plainText,
            cipherText,
            int64 cipherTextLength,
            nonce,
            senderKey,
            recipientKey.Secret)

    if result = 0 then Ok <| PlainText plainText else Error()
let generateKeyPair() =
    let publicKey = Array.zeroCreate publicKeyLength
    let secretKey = Array.zeroCreate secretKeyLength
    let secret = new Secret(secretKey)
    let result = Interop.crypto_box_keypair(publicKey, secretKey)
    if result = 0
    then SecretKeySecret secret, PublicKeyBytes publicKey
    else
        (secret :> IDisposable).Dispose()
        CryptographicException("Encryption key generation failed. This should not happen. Please report this error.")
        |> raise
let generateNonce() = Random.bytes nonceLength |> NonceBytes
