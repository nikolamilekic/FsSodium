[<RequireQualifiedAccess>]
module FsSodium.SecretKeyAuthentication

let private macLength = lazy (Interop.crypto_auth_bytes() |> int)
let private keyLength = lazy (Interop.crypto_auth_keybytes() |> int)

type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        Sodium.initialize ()
        new Key(Random.bytes keyLength.Value)
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> keyLength.Value
        then Error ()
        else Ok <| new Key(x)
type Mac = private | Mac of byte[] with
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> macLength.Value then Error () else Ok <| Mac x
    member this.Get = let (Mac x) = this in x

let sign (key : Key) message =
    Sodium.initialize ()
    let messageLength = Array.length message
    let mac = Array.zeroCreate macLength.Value
    let result =
        Interop.crypto_auth(
            mac,
            message,
            uint64 messageLength,
            key.Get)
    if result = 0 then Ok <| Mac mac
    else Error <| SodiumError result
let verify (key : Key) (Mac mac) message =
    Sodium.initialize ()
    let messageLength = Array.length message
    let result =
        Interop.crypto_auth_verify(
            mac,
            message,
            uint64 messageLength,
            key.Get)
    if result = 0 then Ok () else Error <| SodiumError result
