module FsSodium.PublicKeyEncryption

open System.Security.Cryptography

type SecretKey = private SecretKeyBytes of byte[]
type PublicKey = private PublicKeyBytes of byte[]
type Nonce = private NonceBytes of byte[]
type CipherText = { CipherTextBytes : byte[]; Nonce : Nonce }

let private publicKeyLength = 32;
let private secretKeyLength = 32;
let private nonceLength = 24;
let private macLength = 16;

let encrypt
    (SecretKeyBytes senderKey)
    (PublicKeyBytes recipientKey)
    ((NonceBytes nonceBytes) as nonce, (PlainTextBytes plainText)) =

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
            senderKey)

    if result = 0
    then { CipherTextBytes = cipherText; Nonce = nonce }
    else CryptographicException("Encryption failed. This should not happen. Please report this error.")
         |> raise
let decrypt
    (SecretKeyBytes recipientKey)
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
            recipientKey)

    if result = 0 then Ok <| PlainTextBytes plainText else Error()
let generateKeyPair() =
    let publicKey = Array.zeroCreate publicKeyLength
    let secretKey = Array.zeroCreate secretKeyLength
    let result = Interop.crypto_box_keypair(publicKey, secretKey)
    if result = 0
    then SecretKeyBytes secretKey, PublicKeyBytes publicKey
    else CryptographicException("Encryption key generation failed. This should not happen. Please report this error.")
         |> raise
let generateNonce() =
    let buffer = Array.zeroCreate nonceLength
    Interop.randombytes_buf(buffer, int64 nonceLength)
    NonceBytes buffer
