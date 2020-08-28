[<RequireQualifiedAccess>]
module FsSodium.HashingSHA512

open FSharpPlus
let private hashLength = lazy (Interop.crypto_hash_sha512_bytes() |> int)
let private stateLength = lazy (Interop.crypto_generichash_statebytes() |> int)

type State = private | State of state:byte[] with
    static member Create() =
        Sodium.initialize ()
        let state = Array.zeroCreate stateLength.Value
        let result = Interop.crypto_hash_sha512_init(state)
        if result = 0
        then Ok <| State state
        else Error (SodiumError result)
    member internal this.Get = let (State bytes) = this in bytes

let hashPart (state : State) input =
    Sodium.initialize ()
    let inputLength = Array.length input
    let result =
        Interop.crypto_hash_sha512_update(
            state.Get,
            input,
            uint64 inputLength)
    if result = 0 then Ok () else Error <| SodiumError result
let completeHash (state : State) =
    Sodium.initialize ()
    let state = state.Get
    let hash = Array.zeroCreate (int hashLength.Value)
    let result = Interop.crypto_hash_sha512_final(state, hash)
    if result = 0 then Ok hash else Error <| SodiumError result
let hash input =
    Sodium.initialize ()
    let inputLength = Array.length input
    let hash = Array.zeroCreate (int hashLength.Value)
    let result = Interop.crypto_hash_sha512( hash, input, uint64 inputLength)
    if result = 0 then Ok hash else Error <| SodiumError result
