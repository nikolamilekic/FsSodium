module FsSodium.Tests.StreamEncryptionTests

open System.IO
open Expecto
open Swensen.Unquote
open Milekic.YoLo
open Milekic.YoLo.UpdateResult
open Milekic.YoLo.UpdateResult.Operators
open FsSodium.StreamEncryption

do initializeSodium()

let zeroKey = Array.zeroCreate 32
let stream = Seq.init 10 byte |> Seq.chunkBySize 3 |> Seq.toList
let streamEncryptionJob =
    seq {
        use enumerator = (stream |> List.toSeq).GetEnumerator()
        let rec run index current = seq {
            let currentIsLast = enumerator.MoveNext() |> not
            let currentTag =
                match currentIsLast, index with
                | true, _ -> Final
                | _, 1 -> Push
                | _, 2 -> Rekey
                | _ -> Message
            yield current, currentTag
            if currentIsLast |> not
            then yield! run (index + 1) enumerator.Current
        }
        let empty = enumerator.MoveNext() |> not
        if not empty then yield! run 0 enumerator.Current
    }
    |> List.ofSeq
    |> traverse encryptPart
let makeStreamDecryptionJob = traverse (decryptPart >> UpdateResult.map fst)
let makeEncryptionState =
    State.MakeEncryptionState
    >> Result.failOnError "Encryption state generation failed"
let makeDecryptionState =
    State.MakeDecryptionState
    >> Result.failOnError "Encryption state generation failed"
    |> curry
let encrypt key x =
    let header, state = makeEncryptionState key
    run state x
    |> Result.failOnError "Part encryption failed."
    |> fun (c, _) -> header, c
let decrypt key header x =
    let state = makeDecryptionState key header
    run state x |> Result.map fst

let alice = Key.GenerateDisposable()
let encryptWithFixture () = encrypt alice <| streamEncryptionJob
let decryptWithFixture (header, parts) =
    List.ofSeq parts |> makeStreamDecryptionJob |> decrypt alice header
let getKeyCopy<'e> : UpdateResult<State, StateUpdate, _, 'e> = updateResult {
    let! (state : State) = Update.getState |> liftUpdate
    return state.State.k |> Array.copy
}

[<Tests>]
let tests =
    testList "StreamEncryption" [
        yield testCase "Part roundtrip works" <| fun () ->
            encryptWithFixture ()
            |> decryptWithFixture
            =! Ok stream
        yield testCase "Decrypt fails with missing part" <| fun () ->
            let encrypted =
                let h, c = encryptWithFixture ()
                h, c |> Seq.skip 1
            decryptWithFixture encrypted
            =! (Error <| PartDecryptionError.SodiumError -1)
        yield testCase "Decrypt fails with modified part" <| fun () ->
            let encrypted =
                let h, c = encryptWithFixture ()
                let c = List.ofSeq c
                let bytes = List.head c
                bytes.[0] <- if bytes.[0] = 0uy then 1uy else 0uy
                h, c
            decryptWithFixture encrypted
            =! (Error <| PartDecryptionError.SodiumError -1)
        yield testCase "Decrypt fails with wrong header" <| fun () ->
            let anotherHeader, _ =
                State.MakeEncryptionState(alice)
                |> Result.failOnError "Encryption state generation failed"
            let encrypted =
                let _, c = encryptWithFixture ()
                anotherHeader, c
            decryptWithFixture encrypted
            =! (Error <| PartDecryptionError.SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            encryptWithFixture ()
            |> fun (header, parts) ->
                makeStreamDecryptionJob parts
                |> decrypt (Key.GenerateDisposable()) header
            =! (Error <| PartDecryptionError.SodiumError -1)

        let checkKeyModificationAfterMessage shouldBeModified messageType =
            updateResult {
                let! initialKey = getKeyCopy
                do! encryptPart ([|1uy; 2uy; 3uy|], messageType) >>- ignore
                let! nextKey = getKeyCopy
                if shouldBeModified
                then nextKey <>! initialKey
                else nextKey =! initialKey
            }
            |> encrypt alice
            |> ignore

        yield testCase "Key is not modified after encrypting message" <| fun () ->
            checkKeyModificationAfterMessage false Message
        yield testCase "Key is not modified after encrypting push" <| fun () ->
            checkKeyModificationAfterMessage false Push
        yield testCase "Key is modified after encrypting rekey" <| fun () ->
            checkKeyModificationAfterMessage true Rekey
        yield testCase "Key is modified after encrypting final" <| fun () ->
            checkKeyModificationAfterMessage true Final

        yield testCase "Old state is disposed after encryption" <| fun () ->
            updateResult {
                let! (state : State) = Update.getState |> liftUpdate
                state.State.k <>! zeroKey
                do! encryptPart ([|1uy; 2uy; 3uy|], Message) >>- ignore
                state.State.k =! zeroKey
            }
            |> encrypt alice
            |> ignore
        yield testCase "Old state is disposed after decryption" <| fun () ->
            let h, c = encryptPart ([|1uy; 2uy; 3uy|], Message) |> encrypt alice
            updateResult {
                let! (state : State) = Update.getState |> liftUpdate
                state.State.k <>! zeroKey
                do! decryptPart c >>- ignore
                state.State.k =! zeroKey
            }
            |> decrypt alice h
            =! Ok ()
        yield testCase "Key is copied after encryption" <| fun () ->
            updateResult {
                let! initialKeyCopy = getKeyCopy
                let! (initialState : State) = Update.getState |> liftUpdate
                do! encryptPart ([|1uy; 2uy; 3uy|], Message) >>- ignore
                let! (nextState : State) = Update.getState |> liftUpdate
                initialKeyCopy <>! zeroKey
                initialState.State.k =! zeroKey
                initialKeyCopy =! nextState.State.k
            }
            |> encrypt alice
            |> ignore
        yield testCase "Key is copied after decryption" <| fun () ->
            let header, c =
                encryptPart ([|1uy; 2uy; 3uy|], Message)
                |> encrypt alice

            updateResult {
                let! initialKeyCopy = getKeyCopy
                let! (initialState : State) = Update.getState |> liftUpdate
                do! decryptPart c >>- ignore
                let! (nextState : State) = Update.getState |> liftUpdate
                initialKeyCopy <>! zeroKey
                initialState.State.k =! zeroKey
                initialKeyCopy =! nextState.State.k
            }
            |> decrypt alice header
            =! Ok ()

        let testStreamRoundtripWithLength length () =
            let sourceBuffer = Array.init length byte
            use encryptionSource = new MemoryStream(sourceBuffer)
            let encryptionBuffer = Array.zeroCreate 500
            use encryptionDestination = new MemoryStream(encryptionBuffer)
            let header, _ =
                encryptStream
                    length
                    (readFromStream encryptionSource)
                    (writeToStream encryptionDestination)
                |> encrypt alice

            use decryptionSource =
                let bufer =
                    Array.truncate
                        (int encryptionDestination.Position)
                        encryptionBuffer
                new MemoryStream(bufer)

            let decryptionDestinationBuffer = Array.zeroCreate length
            use decryptionDestination =
                new MemoryStream(decryptionDestinationBuffer)

            decryptStream
                (readFromStream decryptionSource)
                (writeToStream decryptionDestination)
            |> decrypt alice header
            =! Ok()

            decryptionDestinationBuffer =! sourceBuffer

        yield!
            [22; 30]
            |> Seq.map (fun x ->
                testCase
                    (sprintf "Stream roundtrip works with length %i" x)
                    (testStreamRoundtripWithLength x))
    ]
