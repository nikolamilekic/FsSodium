module FsSodium.PublicKeyAuthentication

open System

let private macLength = Interop.crypto_sign_bytes()
let private publicKeyLength = Interop.crypto_sign_publickeybytes()
let private secretKeyLength = Interop.crypto_sign_secretkeybytes()

type SecretKey private (secretKey) =
    inherit Secret(secretKey)
    static member Length = secretKeyLength
    static member Generate() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let secret = new SecretKey(secretKey)
        let result = Interop.crypto_sign_keypair(publicKey, secretKey)
        if result = 0 then Ok (secret, PublicKey publicKey)
        else (secret :> IDisposable).Dispose(); Error <| SodiumError result
    static member Validate x =
        validateArrayLength secretKeyLength (fun x -> new SecretKey(x)) x
and PublicKey =
    private | PublicKey of byte[]
    static member Length = publicKeyLength
    static member Validate x =
        validateArrayLength publicKeyLength PublicKey x
    static member Compute (secretKey : SecretKey) =
        let publicKey = Array.zeroCreate publicKeyLength
        let result =
            Interop.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey.Secret)
        if result = 0 then Ok <| PublicKey publicKey
        else Error <| SodiumError result
    member this.Value = let (PublicKey x) = this in x

type Mac =
    private | Mac of byte[]
    static member Length = macLength
    static member Validate x = validateArrayLength macLength Mac x
    member this.Value = let (Mac x) = this in x

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
    if result = 0 then Ok <| Mac mac
    else Error <| SodiumError result

let verify (PublicKey key) message (Mac mac) =
    let messageLength = Array.length message
    let result =
        Interop.crypto_sign_verify_detached(
            mac,
            message,
            uint64 messageLength,
            key)
    if result = 0 then Ok () else Error <| SodiumError result
