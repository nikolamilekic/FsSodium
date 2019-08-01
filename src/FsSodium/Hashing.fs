module rec FsSodium.Hashing

open Milekic.YoLo
open Extensions

#nowarn "40"

module KeyLength =
    let minimum = Interop.crypto_generichash_keybytes_min()
    let maximum = Interop.crypto_generichash_keybytes_max()
    let recommended =
        Interop.crypto_generichash_keybytes()
        |> KeyLength.Validate
        |> Result.failOnError "Invalid recommended key length."
    let getLength x = if isNull x then 0 else Array.length x
type KeyLength =
    private | KeyLength of int
    static member Validate x =
        validateRange KeyLength.minimum KeyLength.maximum KeyLength x
    member this.Value = let (KeyLength x) = this in x
type Key =
    private | Key of byte[]
    static member Generate (KeyLength x) =
        (if x = 0 then null else Random.bytes x) |> Key
    static member None = Key null
    static member Validate x =
        if isNull x then Key x |> Ok else
        validateRange
            KeyLength.minimum
            KeyLength.maximum
            (fun _ -> Key x)
            (Array.length x)
    member this.Value = let (Key x) = this in x

module HashLength =
    let minimum = Interop.crypto_generichash_bytes_min()
    let maximum = Interop.crypto_generichash_bytes_max()
    let recommended =
        Interop.crypto_generichash_bytes()
        |> HashLength.Validate
        |> Result.failOnError "Invalid recommended hash length."
type HashLength =
    private | HashLength of int
    static member Validate x =
        validateRange HashLength.minimum HashLength.maximum HashLength x
    member this.Value = let (HashLength x) = this in x

type State =
    private | State of byte[] * int
    static member Make(Key k, HashLength hashLength) =
        let state = Array.zeroCreate 361
        let result =
            Interop.crypto_generichash_init(
                state,
                k,
                uint64 (KeyLength.getLength k),
                uint64 hashLength)
        if result = 0
        then Ok <| State (state, hashLength)
        else Error (SodiumError result)
    member internal this.Value = let (State (bytes, length)) = this
                                 bytes, length

let hashPart (state : State) input =
    let inputLength = Array.length input
    let result =
        Interop.crypto_generichash_update(
            fst state.Value,
            input,
            uint64 inputLength)
    if result = 0 then Ok () else Error <| SodiumError result
let completeHash (state : State) =
    let state, hashLength = state.Value
    let hash = Array.zeroCreate hashLength
    let result =
        Interop.crypto_generichash_final(
            state,
            hash,
            uint64 hashLength)
    if result = 0 then Ok hash else Error <| SodiumError result

let hash (Key key) (HashLength hashLength) input =
    let inputLength = Array.length input
    let hash = Array.zeroCreate hashLength
    let result =
        Interop.crypto_generichash(
            hash,
            uint64 hashLength,
            input,
            uint64 inputLength,
            key,
            uint64 (KeyLength.getLength key))
    if result = 0 then Ok hash else Error <| SodiumError result
