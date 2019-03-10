module FsSodium.PublicKeyAuthentication

open System
open System.Security.Cryptography

type SignedText = SignedTextBytes of byte[]
type SecretKey = private SecretKeySecret of Secret
type PublicKey = private PublicKeyBytes of byte[]

let private signatureLength = Interop.crypto_sign_bytes()
let private publicKeyLength = Interop.crypto_sign_publickeybytes()
let private secretKeyLength = Interop.crypto_sign_secretkeybytes()

let sign (SecretKeySecret secret) (PlainText plainText) =
    let plainTextLength = Array.length plainText
    let signedText = Array.zeroCreate (plainTextLength + signatureLength)
    let result =
        Interop.crypto_sign(
            signedText,
            IntPtr.Zero,
            plainText,
            int64 plainTextLength,
            secret.Secret)
    if result = 0
    then SignedTextBytes signedText
    else CryptographicException("Signing failed. This should not happen. Please report this error.")
         |> raise
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
    if result = 0 then Ok <| PlainText plainText else Error()
let generateKeyPair() =
    let publicKey = Array.zeroCreate publicKeyLength
    let secretKey = Array.zeroCreate secretKeyLength
    let secret = new Secret(secretKey)
    let result = Interop.crypto_sign_keypair(publicKey, secretKey)
    if result = 0
    then SecretKeySecret secret, PublicKeyBytes publicKey
    else
        (secret :> IDisposable).Dispose()
        CryptographicException("Authentication key generation failed. This should not happen. Please report this error.")
        |> raise
