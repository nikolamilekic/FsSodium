namespace FsSodium.Hashing

open System
open FSharpPlus

open FsSodium

module internal AlgorithmInfo =
    let hashingKeyMinimumLength = Interop.crypto_generichash_keybytes_min()
    let hashingKeyMaximumLength = Interop.crypto_generichash_keybytes_max()
    let hashingKeyRecommendedLength = Interop.crypto_generichash_keybytes()

    let hashMinimumLength = Interop.crypto_generichash_bytes_min()
    let hashMaximumLength = Interop.crypto_generichash_bytes_max()
    let hashRecommendedLength = Interop.crypto_generichash_bytes()

open AlgorithmInfo

type HashingKeyLength = private | HashingKeyLength of uint32 with
    static member Minimum = HashingKeyLength hashingKeyMinimumLength
    static member Maximum = HashingKeyLength hashingKeyMaximumLength
    static member Recommended = HashingKeyLength hashingKeyRecommendedLength
    static member Custom x =
        x
        |> Result.protect uint32
        |> first ignore
        >>= (fun x ->
            if x < hashingKeyMinimumLength || x > hashingKeyMaximumLength
            then Error ()
            else Ok <| HashingKeyLength x)
    member this.Get = let (HashingKeyLength x) = this in x
type HashingKey = private | HashingKey of byte[] with
    static member Generate (HashingKeyLength x) =
        (if x = 0u then null else Random.bytes (int x)) |> HashingKey
    static member None = HashingKey null
    static member Import x =
        if isNull x then HashingKey x |> Ok else
        Array.length x |> HashingKeyLength.Custom |>> konst (HashingKey x)
    member this.Get = let (HashingKey x) = this in x
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
type HashingState = private | HashingState of state:byte[] * hashLength:uint32 with
    static member Create(HashingKey k, HashLength hashLength) =
        let state = Array.zeroCreate 361
        let keyLength = if isNull k then 0 else Array.length k
        let result =
            Interop.crypto_generichash_init(
                state, k, uint32 keyLength, hashLength)
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
        let hash = Array.zeroCreate (int hashLength)
        let result =
            Interop.crypto_generichash_final(state, hash, hashLength)
        if result = 0 then Ok hash else Error <| SodiumError result
    let hash (HashingKey key) (HashLength hashLength) input =
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
