module FsSodium.PublicKeyAuthentication

open System

let private macLength = Interop.crypto_sign_bytes()
let private publicKeyLength = Interop.crypto_sign_publickeybytes()
let private secretKeyLength = Interop.crypto_sign_secretkeybytes()
type PublicKeyComputationError =
    | SecretKeyIsOfWrongLength
    | SodiumError of int

type PublicKey = private PublicKey of byte[]
    with
        static member Compute secretKey =
            if Array.length secretKey <> secretKeyLength
            then Error PublicKeyComputationError.SecretKeyIsOfWrongLength
            else
            let publicKey = Array.zeroCreate publicKeyLength
            let result = Interop.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey)
            if result = 0 then Ok <| PublicKey publicKey
            else Error <| SodiumError result
type KeyGenerationError = SodiumError of int
type SecretKey private (secretKey, publicKey) =
    inherit Secret(secretKey)
    member __.PublicKey = publicKey
    static member GenerateDisposable() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let secret = new SecretKey(secretKey, PublicKey publicKey)
        let result = Interop.crypto_sign_keypair(publicKey, secretKey)
        if result = 0 then Ok secret
        else (secret :> IDisposable).Dispose(); Error <| SodiumError result

type SigningError = SodiumError of int
let sign (secretKey : SecretKey) message =
    let messageLength = Array.length message
    let mac = Array.zeroCreate macLength
    let result =
        Interop.crypto_sign_detached(
            mac,
            IntPtr.Zero,
            message,
            uint64 messageLength,
            secretKey.Secret)
    if result = 0 then Ok mac
    else Error <| SodiumError result

type MacVerificationError = MacHasWrongLength | SodiumError of int
let verify (PublicKey key) message mac =
    if Array.length mac <> macLength then Error MacHasWrongLength else
    let messageLength = Array.length message
    let result =
        Interop.crypto_sign_verify_detached(
            mac,
            message,
            uint64 messageLength,
            key)
    if result = 0 then Ok () else Error <| SodiumError result
