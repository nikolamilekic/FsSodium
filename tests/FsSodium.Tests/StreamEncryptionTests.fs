module FsSodium.Tests.StreamEncryptionTests

open System
open System.IO
open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus
open FSharpPlus.Data

open FsSodium

initializeSodium()

let createEncryptionState =
    StreamEncryption.createEncryptionState
    >> Result.failOnError "Encryption state generation failed"
let createDecryptionState =
    StreamEncryption.createDecryptionState
    >> Result.failOnError "Encryption state generation failed"

let Message = StreamEncryption.Message
let Push = StreamEncryption.Push
let Rekey = StreamEncryption.Rekey
let Final = StreamEncryption.Final

let testMessages =
    Seq.init 10 byte
    |> Seq.chunkBySize 3
    |> Seq.zip [ Message; Push; Rekey; Final ]
    |> toList
let encryptTestMessages key = monad.strict {
    let (header, state) = createEncryptionState key
    let! cipherTexts =
        testMessages
        |>> StreamEncryption.encryptPart
        |> sequence
        |> fun (x : StateT<_, Result<byte[] list * _, _>>) -> StateT.run x state
        |>> fst
    return header, cipherTexts
}
let decryptTestMessages key (header, cipherTexts : byte[] list) =
    let state = createDecryptionState(key, header)
    cipherTexts
    |>> StreamEncryption.decryptPart
    |> sequence
    |> fun (x : StateT<_, Result<(StreamEncryption.MessageType * byte[]) list * _, _>>) ->
        StateT.run x state
    |>> fst

let zeros = Array.zeroCreate 32
let alice = StreamEncryption.Key.Generate()
let eve = StreamEncryption.Key.Generate()

let copyStateKey : StateT<StreamEncryption.State, Result<_, _>> = monad {
    let! state = State.get |> StateT.hoist
    return state.State.k |> Array.copy
}

[<Tests>]
let tests =
    testList "StreamEncryption" [
        yield testCase "Part roundtrip works" <| fun () ->
            encryptTestMessages alice
            |> Result.failOnError "Encryption failed"
            |> decryptTestMessages alice
            =! Ok testMessages
        yield testCase "Decrypt fails with missing part" <| fun () ->
            let header, cipherTexts =
                encryptTestMessages alice
                |> Result.failOnError "Encryption failed"
            let cipherTexts = skip 1 cipherTexts
            decryptTestMessages alice (header, cipherTexts)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with modified part" <| fun () ->
            let header, cipherTexts =
                encryptTestMessages alice
                |> Result.failOnError "Encryption failed"
            let head = List.head cipherTexts
            head.[0] <- if head.[0] = 0uy then 1uy else 0uy
            decryptTestMessages alice (header, cipherTexts)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong header" <| fun () ->
            let anotherHeader, _ = createEncryptionState alice
            let _, cipherTexts =
                encryptTestMessages alice
                |> Result.failOnError "Encryption failed"
            let cipherTexts = skip 1 cipherTexts
            decryptTestMessages alice (anotherHeader, cipherTexts)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let header, cipherTexts =
                encryptTestMessages alice
                |> Result.failOnError "Encryption failed"
            decryptTestMessages eve (header, cipherTexts)
            =! (Error <| SodiumError -1)

        let checkKeyModificationAfterMessage shouldBeModified messageType =
            let (_, state) = createEncryptionState alice
            monad {
                let! initialKey = copyStateKey
                do!
                    StreamEncryption.encryptPart (messageType, [|1uy; 2uy; 3uy|])
                    |>> ignore
                let! nextKey = copyStateKey
                if shouldBeModified
                then nextKey <>! initialKey
                else nextKey =! initialKey
            }
            |> StateT.run <| state
            |>> fst
            =! Ok ()

        yield testCase "Key is not modified after encrypting message" <| fun () ->
            checkKeyModificationAfterMessage false Message
        yield testCase "Key is not modified after encrypting push" <| fun () ->
            checkKeyModificationAfterMessage false Push
        yield testCase "Key is modified after encrypting rekey" <| fun () ->
            checkKeyModificationAfterMessage true Rekey
        yield testCase "Key is modified after encrypting final" <| fun () ->
            checkKeyModificationAfterMessage true Final

        yield testCase "Old state is disposed after encryption" <| fun () ->
            let (_, state) = createEncryptionState alice
            monad {
                let! (state : StreamEncryption.State) = State.get |> StateT.hoist
                state.State.k <>! zeros
                do!
                    StreamEncryption.encryptPart (Message, [|1uy; 2uy; 3uy|])
                    |>> ignore
                state.State.k =! zeros
            }
            |> StateT.run <| state
            |>> ignore
            =! Ok ()
        yield testCase "Old state is disposed after decryption" <| fun () ->
            let (h, state) = createEncryptionState alice
            let c =
                StreamEncryption.encryptPart (Message, [|1uy; 2uy; 3uy|])
                |> StateT.run <| state
                |>> fst
                |> Result.failOnError "Encryption failed"
            monad {
                let! (state : StreamEncryption.State) = State.get |> StateT.hoist
                state.State.k <>! zeros
                do! StreamEncryption.decryptPart c |>> ignore
                state.State.k =! zeros
            }
            |> StateT.run <| createDecryptionState (alice, h)
            |>> ignore
            =! Ok ()
        yield testCase "Key is copied after encryption" <| fun () ->
            let (_, state) = createEncryptionState alice
            monad {
                let! initialKey = copyStateKey
                let! (initialState : StreamEncryption.State) = State.get |> StateT.hoist
                do!
                    StreamEncryption.encryptPart (Message, [|1uy; 2uy; 3uy|])
                    |>> ignore
                let! (nextState : StreamEncryption.State) =
                    State.get |> StateT.hoist
                initialKey <>! zeros
                initialState.State.k =! zeros
                initialKey =! nextState.State.k
            }
            |> StateT.run <| state
            |>> ignore
            =! Ok ()
        yield testCase "Key is copied after decryption" <| fun () ->
            let (h, state) = createEncryptionState alice
            let c =
                StreamEncryption.encryptPart (Message, [|1uy; 2uy; 3uy|])
                |> StateT.run <| state
                |>> fst
                |> Result.failOnError "Encryption failed"

            monad {
                let! initialKeyCopy = copyStateKey
                let! (initialState : StreamEncryption.State) =
                    State.get |> StateT.hoist
                do! StreamEncryption.decryptPart c |>> ignore
                let! (nextState : StreamEncryption.State) = State.get |> StateT.hoist
                initialKeyCopy <>! zeros
                initialState.State.k =! zeros
                initialKeyCopy =! nextState.State.k
            }
            |> StateT.run <| createDecryptionState (alice, h)
            |>> ignore
            =! Ok ()
    ]
