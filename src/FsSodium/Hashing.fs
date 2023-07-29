[<RequireQualifiedAccess>]
module FsSodium.Hashing

open FSharpPlus

let private hashingKeyMinimumLength = lazy Interop.crypto_generichash_keybytes_min()
let private hashingKeyMaximumLength = lazy Interop.crypto_generichash_keybytes_max()
let private hashingKeyRecommendedLength = lazy Interop.crypto_generichash_keybytes()
let private hashMinimumLength = lazy Interop.crypto_generichash_bytes_min()
let private hashMaximumLength = lazy Interop.crypto_generichash_bytes_max()
let private hashRecommendedLength = lazy Interop.crypto_generichash_bytes()
let private stateLength = lazy (Interop.crypto_generichash_statebytes() |> int)

type KeyLength = private | KeyLength of uint32 with
    static member Minimum =
        Sodium.initialize ()
        KeyLength hashingKeyMinimumLength.Value
    static member Maximum =
        Sodium.initialize ()
        KeyLength hashingKeyMaximumLength.Value
    static member Recommended =
        Sodium.initialize ()
        KeyLength hashingKeyRecommendedLength.Value
    static member Custom x =
        Sodium.initialize ()

        x
        |> Result.protect uint32
        |> Result.mapError ignore
        >>= (fun x ->
            if x < hashingKeyMinimumLength.Value ||
                x > hashingKeyMaximumLength.Value
            then Error ()
            else Ok <| KeyLength x)
    member this.Get = let (KeyLength x) = this in x
type Key = private | Key of byte[] with
    static member Generate (KeyLength x) =
        (if x = 0u then null else Random.bytes (int x)) |> Key
    static member None = Key null
    static member Import x =
        if isNull x then Key x |> Ok else
        Array.length x |> KeyLength.Custom |>> konst (Key x)
    member this.Get = let (Key x) = this in x
type HashLength = private | HashLength of uint32 with
    static member Minimum =
        Sodium.initialize ()
        HashLength hashMinimumLength.Value
    static member Maximum =
        Sodium.initialize ()
        HashLength hashMaximumLength.Value
    static member Recommended =
        Sodium.initialize ()
        HashLength hashRecommendedLength.Value
    static member Custom x =
        Sodium.initialize ()

        x
        |> Result.protect uint32
        |> Result.mapError ignore
        >>= (fun x ->
            if x < hashMinimumLength.Value ||
                x > hashMaximumLength.Value
            then Error ()
            else Ok <| HashLength x)
    member this.Get = let (HashLength x) = this in x
type State = private | State of state:byte[] * hashLength:uint32 with
    static member Create(Key k, HashLength hashLength) =
        Sodium.initialize ()
        let state = Array.zeroCreate stateLength.Value
        let keyLength = if isNull k then 0 else Array.length k
        let result =
            Interop.crypto_generichash_init(
                state, k, uint32 keyLength, hashLength)
        if result = 0
        then Ok <| State (state, hashLength)
        else Error (SodiumError result)
    member internal this.Get =
        let (State (bytes, length)) = this in bytes, length

let hashPartWithLength (state : State) input inputLength =
    Sodium.initialize ()
    let result =
        Interop.crypto_generichash_update(
            fst state.Get,
            input,
            uint64 inputLength)
    if result = 0 then Ok () else Error <| SodiumError result
let hashPart state input = hashPartWithLength state input (Array.length input)
let completeHash (state : State) =
    Sodium.initialize ()
    let state, hashLength = state.Get
    let hash = Array.zeroCreate (int hashLength)
    let result =
        Interop.crypto_generichash_final(state, hash, hashLength)
    if result = 0 then Ok hash else Error <| SodiumError result
let hashWithLength (Key key) (HashLength hashLength) input inputLength =
    Sodium.initialize ()
    let hash = Array.zeroCreate (int hashLength)
    let keyLength = if isNull key then 0 else Array.length key
    let result =
        Interop.crypto_generichash(
            hash,
            hashLength,
            input,
            uint64 inputLength,
            key,
            uint32 keyLength)
    if result = 0 then Ok hash else Error <| SodiumError result
let hash key hashLength input =
    hashWithLength key hashLength input (Array.length input)
