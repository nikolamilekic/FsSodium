module FsSodium.Tests.StreamEncryptionTests

open System
open System.IO
open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsCheck
open FSharpPlus
open FSharpPlus.Data

open FsSodium
open FsSodium.StreamEncryption
open AlgorithmInfo

initializeSodium()

type Generators =
    static member ChunkLength() =
        Gen.choose(1, (Int32.MaxValue - macLength))
        |> Gen.map (ChunkLength.Validate >> Result.get)
        |> Arb.fromGen
let config = { FsCheckConfig.defaultConfig with arbitrary = [typeof<Generators>] }
let testProperty =  testPropertyWithConfig config

let createEncryptionState =
    State.CreateEncryptionState
    >> Result.failOnError "Encryption state generation failed"
let createDecryptionState =
    State.CreateDecryptionState
    >> Result.failOnError "Encryption state generation failed"
let testMessages =
    Seq.init 10 byte
    |> Seq.chunkBySize 3
    |> Seq.zip [ Message; Push; Rekey; Final ]
    |> toList
let encryptTestMessages key = monad.strict {
    let! (header, state) = State.CreateEncryptionState key
    let! cipherTexts =
        testMessages
        |>> StreamEncryption.encryptPart
        |> sequence
        |> fun (x : StateT<_, Result<byte[] list * _, _>>) -> StateT.run x state
        |>> fst
    return header, cipherTexts
}
let decryptTestMessages key (header, cipherTexts : byte[] list) = monad.strict {
    let! state = State.CreateDecryptionState(key, header)
    return!
        cipherTexts
        |>> StreamEncryption.decryptPart
        |> sequence
        |> fun (x : StateT<_, Result<(MessageType * byte[]) list * _, _>>) ->
            StateT.run x state
        |>> fst
}

let zeros = Array.zeroCreate 32
let alice = Key.Generate()
let eve = Key.Generate()

let copyStateKey : StateT<State, Result<_, _>> = monad {
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
                let! (state : State) = State.get |> StateT.hoist
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
                let! (state : State) = State.get |> StateT.hoist
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
                let! (initialState : State) = State.get |> StateT.hoist
                do!
                    StreamEncryption.encryptPart (Message, [|1uy; 2uy; 3uy|])
                    |>> ignore
                let! (nextState : State) = State.get |> StateT.hoist
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
                let! (initialState : State) = State.get |> StateT.hoist
                do! StreamEncryption.decryptPart c |>> ignore
                let! (nextState : State) = State.get |> StateT.hoist
                initialKeyCopy <>! zeros
                initialState.State.k =! zeros
                initialKeyCopy =! nextState.State.k
            }
            |> StateT.run <| createDecryptionState (alice, h)
            |>> ignore
            =! Ok ()

        let chunkLength =
            ChunkLength.Validate 10
            |> Result.failOnError "Unable to create chunk length"

        let testStreamRoundtripWithLength length () =
            let sourceBuffer = Random.bytes length
            use encryptionSource = new MemoryStream(sourceBuffer)
            let encryptionBuffer = Array.zeroCreate 500
            use encryptionDestination = new MemoryStream(encryptionBuffer)
            let header =
                StreamEncryption.encryptStream
                    alice chunkLength encryptionSource encryptionDestination
                |> Result.failOnError "Part encryption failed."

            int encryptionDestination.Position
            =! StreamEncryption.getCipherTextStreamLength chunkLength length

            use decryptionSource =
                let bufer =
                    Array.truncate
                        (int encryptionDestination.Position)
                        encryptionBuffer
                new MemoryStream(bufer)

            let decryptionDestinationBuffer = Array.zeroCreate length
            use decryptionDestination =
                new MemoryStream(decryptionDestinationBuffer)

            StreamEncryption.decryptStream
                (alice, header)
                chunkLength
                decryptionSource
                decryptionDestination
            =! Ok()

            decryptionDestinationBuffer =! sourceBuffer

        yield!
            [5; 10; 22; 30]
            |> Seq.map (fun x ->
                testCase
                    (sprintf "Stream roundtrip works with length %i" x)
                    (testStreamRoundtripWithLength x))

        yield testProperty "Get plaintext / ciphertext length roundtrip"
            <| fun (chunk, length) ->
            length > 0 ==> lazy
            (StreamEncryption.getCipherTextStreamLength chunk length
            |> StreamEncryption.getPlainTextStreamLength chunk) =! length
    ]
