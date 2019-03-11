module FsSodium.PublicKeyAuthentication

open System
open System.Security.Cryptography
open Chessie.ErrorHandling

let private macLength = Interop.crypto_sign_bytes()
let private publicKeyLength = Interop.crypto_sign_publickeybytes()
let private secretKeyLength = Interop.crypto_sign_secretkeybytes()

type PublicKey = private PublicKey of byte[]
type SecretKey private (secretKey, publicKey) =
    inherit Secret(secretKey)
    member __.PublicKey = publicKey
    static member CreateDisposable() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let secret = new SecretKey(secretKey, PublicKey publicKey)
        let result = Interop.crypto_sign_keypair(publicKey, secretKey)
        if result = 0 then secret
        else
            (secret :> IDisposable).Dispose()
            CryptographicException("Authentication key generation failed. This should not happen. Please report this error.")
            |> raise

let sign (secretKey : SecretKey) message =
    let messageLength = Array.length message
    let mac = Array.zeroCreate macLength
    let result =
        Interop.crypto_sign_detached(
            mac,
            IntPtr.Zero,
            message,
            int64 messageLength,
            secretKey.Secret)
    if result = 0 then mac
    else CryptographicException("Signing failed. This should not happen. Please report this error.")
         |> raise
let verify (PublicKey key) message mac =
    if Array.length mac <> macLength then fail "Mac must be %d bytes long." else
    let messageLength = Array.length message
    let result =
        Interop.crypto_sign_verify_detached(
            mac,
            message,
            int64 messageLength,
            key)
    if result = 0 then ok () else fail "Authentication failed"
