module FsSodium.PublicKeyAuthentication

open System

type SecretKey = private SecretKeyBytes of byte[]
type PublicKey = private PublicKeyBytes of byte[]

let private signatureLength = 64
let private publicKeyLength = 32
let private secretKeyLength = 64

let sign (SecretKeyBytes secretKey) (PlainTextBytes plainText) =
    let plainTextLength = Array.length plainText
    let signedText = Array.zeroCreate (plainTextLength + signatureLength)
    let result =
        Interop.crypto_sign(
            signedText,
            IntPtr.Zero,
            plainText,
            int64 plainTextLength,
            secretKey)
    if result = 0 then Ok <| SignedTextBytes signedText else Error()
let verify (PublicKeyBytes key) (SignedTextBytes signedText) =
    let signedTextLength = Array.length signedText
    let plainText = Array.zeroCreate (signedTextLength - signatureLength)
    let result =
        Interop.crypto_sign_open(
            plainText,
            IntPtr.Zero,
            signedText,
            int64 signedTextLength,
            key)
    if result = 0 then Ok <| PlainTextBytes plainText else Error()
let generateKeyPair() =
    let publicKey = Array.zeroCreate publicKeyLength
    let secretKey = Array.zeroCreate secretKeyLength
    let result = Interop.crypto_sign_keypair(publicKey, secretKey)
    if result = 0
    then Ok <| (PublicKeyBytes publicKey, SecretKeyBytes secretKey)
    else Error()
