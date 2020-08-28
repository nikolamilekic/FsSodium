[<RequireQualifiedAccess>]
module FsSodium.Hashing

open FSharpPlus

let private hashingKeyMinimumLength = Interop.crypto_generichash_keybytes_min()
let private hashingKeyMaximumLength = Interop.crypto_generichash_keybytes_max()
let private hashingKeyRecommendedLength = Interop.crypto_generichash_keybytes()
let private hashMinimumLength = Interop.crypto_generichash_bytes_min()
let private hashMaximumLength = Interop.crypto_generichash_bytes_max()
let private hashRecommendedLength = Interop.crypto_generichash_bytes()

let stateLength = Interop.crypto_generichash_statebytes() |> int

type KeyLength = private | KeyLength of uint32 with
    static member Minimum = KeyLength hashingKeyMinimumLength
    static member Maximum = KeyLength hashingKeyMaximumLength
    static member Recommended = KeyLength hashingKeyRecommendedLength
    static member Custom x =
        x
        |> Result.protect uint32
        |> first ignore
        >>= (fun x ->
            if x < hashingKeyMinimumLength || x > hashingKeyMaximumLength
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
    static member Minimum = HashLength hashMinimumLength
    static member Maximum = HashLength hashMaximumLength
    static member Recommended = HashLength hashRecommendedLength
    static member Custom x =
        x
        |> Result.protect uint32
        |> first ignore
        >>= (fun x ->
            if x < hashMinimumLength || x > hashMaximumLength
            then Error ()
            else Ok <| HashLength x)
    member this.Get = let (HashLength x) = this in x
type State = private | State of state:byte[] * hashLength:uint32 with
    static member Create(Key k, HashLength hashLength) =
        let state = Array.zeroCreate (stateLength)
        let keyLength = if isNull k then 0 else Array.length k
        let result =
            Interop.crypto_generichash_init(
                state, k, uint32 keyLength, hashLength)
        if result = 0
        then Ok <| State (state, hashLength)
        else Error (SodiumError result)
    member internal this.Get =
        let (State (bytes, length)) = this in bytes, length

let hashPart (state : State) input =
    let inputLength = Array.length input
    let result =
        Interop.crypto_generichash_update(
            fst state.Get,
            input,
            uint64 inputLength)
    if result = 0 then Ok () else Error <| SodiumError result
let completeHash (state : State) =
    let state, hashLength = state.Get
    let hash = Array.zeroCreate (int hashLength)
    let result =
        Interop.crypto_generichash_final(state, hash, hashLength)
    if result = 0 then Ok hash else Error <| SodiumError result
let hash (Key key) (HashLength hashLength) input =
    let inputLength = Array.length input
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
