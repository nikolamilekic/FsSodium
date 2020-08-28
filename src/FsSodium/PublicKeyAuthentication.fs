namespace FsSodium.PublicKeyAuthentication

open System
open FsSodium

module internal AlgorithmInfo =
    let macLength = Interop.crypto_sign_bytes() |> int
    let publicKeyLength = Interop.crypto_sign_publickeybytes() |> int
    let secretKeyLength = Interop.crypto_sign_secretkeybytes() |> int

open AlgorithmInfo

type SecretKey private (secretKey) =
    inherit Secret(secretKey)
    static member Generate() =
        let publicKey = Array.zeroCreate publicKeyLength
        let secretKey = Array.zeroCreate secretKeyLength
        let result = Interop.crypto_sign_keypair(publicKey, secretKey)
        if result = 0 then Ok (new SecretKey(secretKey), PublicKey publicKey)
        else Error <| SodiumError result
    static member Import x =
        if Array.length x <> secretKeyLength
        then Error ()
        else Ok <| new SecretKey(x)
and PublicKey = private | PublicKey of byte[] with
    static member Import x =
        if Array.length x <> publicKeyLength then Error () else Ok <| PublicKey x
    static member FromSecretKey (secretKey : SecretKey) =
        let publicKey = Array.zeroCreate publicKeyLength
        let result =
            Interop.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey.Get)
        if result = 0 then Ok <| PublicKey publicKey
        else Error <| SodiumError result
    member this.Get = let (PublicKey x) = this in x
type Mac = private | Mac of byte[] with
    static member Import x =
        if Array.length x <> macLength then Error () else Ok <| Mac x
    member this.Get = let (Mac x) = this in x

[<RequireQualifiedAccess>]
module PublicKeyAuthentication =
    let sign (secretKey : SecretKey) message =
        let messageLength = Array.length message
        let mac = Array.zeroCreate macLength
        let result =
            Interop.crypto_sign_detached(
                mac,
                IntPtr.Zero,
                message,
                uint64 messageLength,
                secretKey.Get)
        if result = 0 then Ok <| Mac mac
        else Error <| SodiumError result
    let verify (PublicKey key) (message, (Mac mac)) =
        let messageLength = Array.length message
        let result =
            Interop.crypto_sign_verify_detached(
                mac,
                message,
                uint64 messageLength,
                key)
        if result = 0 then Ok () else Error <| SodiumError result
