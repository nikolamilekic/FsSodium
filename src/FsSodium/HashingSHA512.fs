namespace FsSodium.Hashing.SHA512

open FSharpPlus
open FsSodium

module internal AlgorithmInfoSHA512 =
    let hashLength = Interop.crypto_hash_sha512_bytes() |> int
    let stateLength = Interop.crypto_generichash_statebytes() |> int

open AlgorithmInfoSHA512

type SHA512State = private | HashingState of state:byte[] with
    static member Create() =
        let state = Array.zeroCreate stateLength
        let result = Interop.crypto_hash_sha512_init(state)
        if result = 0
        then Ok <| HashingState state
        else Error (SodiumError result)
    member internal this.Get = let (HashingState bytes) = this in bytes

[<RequireQualifiedAccess>]
module SHA512 =
    let hashPart (state : SHA512State) input =
        let inputLength = Array.length input
        let result =
            Interop.crypto_hash_sha512_update(
                state.Get,
                input,
                uint64 inputLength)
        if result = 0 then Ok () else Error <| SodiumError result
    let completeHash (state : SHA512State) =
        let state = state.Get
        let hash = Array.zeroCreate (int hashLength)
        let result = Interop.crypto_hash_sha512_final(state, hash)
        if result = 0 then Ok hash else Error <| SodiumError result
    let hash input =
        let inputLength = Array.length input
        let hash = Array.zeroCreate (int hashLength)
        let result = Interop.crypto_hash_sha512( hash, input, uint64 inputLength)
        if result = 0 then Ok hash else Error <| SodiumError result
