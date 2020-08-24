namespace FsSodium.Hashing

open FSharpPlus
open FSharpPlus.Data

open FsSodium

type HashingKeyLength = private | HashingKeyLength of int with
    static member Minimum =
        Interop.crypto_generichash_keybytes_min() |> HashingKeyLength
    static member Maximum =
        Interop.crypto_generichash_keybytes_max() |> HashingKeyLength
    static member Recommended =
        Interop.crypto_generichash_keybytes() |> HashingKeyLength
    static member Custom x =
        let result = HashingKeyLength x
        if result < HashingKeyLength.Minimum || result > HashingKeyLength.Maximum
        then Failure ()
        else Success result
    member this.Get = let (HashingKeyLength x) = this in x
type HashingKey = private | HashingKey of byte[] with
    static member Generate (HashingKeyLength x) =
        (if x = 0 then null else Random.bytes x) |> HashingKey
    static member None = HashingKey null
    static member Create x =
        if isNull x then HashingKey x |> Success else
        Array.length x |> HashingKeyLength.Custom |>> konst (HashingKey x)
    member this.Get = let (HashingKey x) = this in x
type HashLength = private | HashLength of int with
    static member Minimum =
        Interop.crypto_generichash_bytes_min() |> HashLength
    static member Maximum =
        Interop.crypto_generichash_bytes_max() |> HashLength
    static member Recommended =
        Interop.crypto_generichash_bytes() |> HashLength
    static member Custom x =
        let result = HashLength x
        if result < HashLength.Minimum || result > HashLength.Maximum
        then Failure ()
        else Success result
    member this.Value = let (HashLength x) = this in x
type HashingState = private | HashingState of state:byte[] * hashLength:int with
    static member Create(HashingKey k, HashLength hashLength) =
        let state = Array.zeroCreate 361
        let keyLength = if isNull k then 0 else Array.length k
        let result =
            Interop.crypto_generichash_init(
                state,
                k,
                uint64 keyLength,
                uint64 hashLength)
        if result = 0
        then Ok <| HashingState (state, hashLength)
        else Error (SodiumError result)
    member internal this.Get =
        let (HashingState (bytes, length)) = this in bytes, length

[<RequireQualifiedAccess>]
module Hashing =
    let hashPart (state : HashingState) input =
        let inputLength = Array.length input
        let result =
            Interop.crypto_generichash_update(
                fst state.Get,
                input,
                uint64 inputLength)
        if result = 0 then Ok () else Error <| SodiumError result
    let completeHash (state : HashingState) =
        let state, hashLength = state.Get
        let hash = Array.zeroCreate hashLength
        let result =
            Interop.crypto_generichash_final(
                state,
                hash,
                uint64 hashLength)
        if result = 0 then Ok hash else Error <| SodiumError result
    let hash (HashingKey key) (HashLength hashLength) input =
        let inputLength = Array.length input
        let hash = Array.zeroCreate hashLength
        let keyLength = if isNull key then 0 else Array.length key
        let result =
            Interop.crypto_generichash(
                hash,
                uint64 hashLength,
                input,
                uint64 inputLength,
                key,
                uint64 keyLength)
        if result = 0 then Ok hash else Error <| SodiumError result
