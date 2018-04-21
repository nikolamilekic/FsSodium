module FsSodium.PublicKeyEncryption

type SecretKey = private SecretKeyBytes of byte[]
type PublicKey = private PublicKeyBytes of byte[]
type Nonce = private NonceBytes of byte[]

let private publicKeyLength = 32;
let private secretKeyLength = 32;
let private nonceLength = 24;
let private macLength = 16;

let encrypt
    (SecretKeyBytes senderKey)
    (PublicKeyBytes recipientKey)
    ((NonceBytes nonce), (PlainTextBytes plainText)) =

    let plainTextLength = Array.length plainText
    let cipherTextLength = macLength + plainTextLength
    let cipherText = Array.zeroCreate cipherTextLength

    let result =
        Interop.crypto_box_easy(
            cipherText,
            plainText,
            int64 plainTextLength,
            nonce,
            recipientKey,
            senderKey)

    if result = 0 then Ok <| CipherTextBytes cipherText else Error()
let decrypt
    (SecretKeyBytes recipientKey)
    (PublicKeyBytes senderKey)
    ((NonceBytes nonce), (CipherTextBytes cipherText)) =

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
    then Ok <| (PublicKeyBytes publicKey, SecretKeyBytes secretKey)
    else Error()
let generateNonce() =
    let buffer = Array.zeroCreate nonceLength
    Interop.randombytes_buf(buffer, int64 nonceLength)
    NonceBytes buffer
