[<RequireQualifiedAccess>]
module FsSodium.PublicKeyAuthentication

open System

let private macLength = lazy (Interop.crypto_sign_bytes() |> int)
let private publicKeyLength = lazy (Interop.crypto_sign_publickeybytes() |> int)
let private secretKeyLength = lazy (Interop.crypto_sign_secretkeybytes() |> int)

type SecretKey private (secretKey) =
    inherit Secret(secretKey)
    static member Generate() =
        Sodium.initialize ()
        let publicKey = Array.zeroCreate publicKeyLength.Value
        let secretKey = Array.zeroCreate secretKeyLength.Value
        let result = Interop.crypto_sign_keypair(publicKey, secretKey)
        if result = 0 then Ok (new SecretKey(secretKey), PublicKey publicKey)
        else Error <| SodiumError result
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> secretKeyLength.Value
        then Error ()
        else Ok <| new SecretKey(x)
and PublicKey = private | PublicKey of byte[] with
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> publicKeyLength.Value
        then Error ()
        else Ok <| PublicKey x
    static member FromSecretKey (secretKey : SecretKey) =
        Sodium.initialize ()
        let publicKey = Array.zeroCreate publicKeyLength.Value
        let result =
            Interop.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey.Get)
        if result = 0 then Ok <| PublicKey publicKey
        else Error <| SodiumError result
    member this.Get = let (PublicKey x) = this in x
type Mac = private | Mac of byte[] with
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> macLength.Value then Error () else Ok <| Mac x
    member this.Get = let (Mac x) = this in x

let signWithLength (secretKey : SecretKey) message messageLength =
    Sodium.initialize ()
    let mac = Array.zeroCreate macLength.Value
    let result =
        Interop.crypto_sign_detached(
            mac,
            IntPtr.Zero,
            message,
            uint64 messageLength,
            secretKey.Get)
    if result = 0 then Ok <| Mac mac
    else Error <| SodiumError result
let sign secretKey message =
    signWithLength secretKey message (Array.length message)
let verifyWithLength (PublicKey key) (Mac mac) message messageLength =
    Sodium.initialize ()
    let result =
        Interop.crypto_sign_verify_detached(
            mac,
            message,
            uint64 messageLength,
            key)
    if result = 0 then Ok () else Error <| SodiumError result
let verify publicKey mac message =
    verifyWithLength publicKey mac message (Array.length message)
