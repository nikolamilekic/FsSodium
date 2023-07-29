[<RequireQualifiedAccess>]
module FsSodium.XSalsa20

open FSharpPlus

let private keyLength = lazy (Interop.crypto_stream_keybytes() |> int)
let private nonceLength = lazy (Interop.crypto_stream_noncebytes() |> int)

type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        Sodium.initialize ()
        new Key(Random.bytes keyLength.Value)
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> keyLength.Value then Error () else Ok <| new Key(x)
type Nonce = private | Nonce of byte[] with
    member this.Get = let (Nonce x) = this in x
    static member Generate() =
        Sodium.initialize ()
        Random.bytes nonceLength.Value |> Nonce
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> nonceLength.Value then Error () else Ok <| Nonce x

let encryptDecryptTo (key : Key) (Nonce nonce) input output length =
    Sodium.initialize ()
    if Array.length input < length then
        invalidArg "input" "Provided input buffer is too small"
    if Array.length output < length then
        invalidArg "output" "Provided output buffer is too small"

    let result =
        Interop.crypto_stream_xor(
            output,
            input,
            uint64 length,
            nonce,
            key.Get)

    if result = 0 then Ok () else Error <| SodiumError result
let encryptDecrypt key nonce input =
    let length = Array.length input
    let output = Array.zeroCreate length
    encryptDecryptTo key nonce input output length
    |>> konst output
