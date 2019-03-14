module FsSodium.Tests.StreamEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open Milekic.YoLo.Result.Operators
open FsSodium

open StreamEncryption

do initializeSodium()

let zeroKey = Array.zeroCreate 32
let stream = Seq.init 10 byte |> Seq.chunkBySize 3 |> Seq.toList
let makeEncryptionState =
    State.MakeEncryptionState
    >> Result.failOnError "Encryption state generation failed"
let encrypt key (parts : _ seq) =
    let partsWithType = seq {
        use enumerator = parts.GetEnumerator()
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
    let header, state = makeEncryptionState key
    let encryptPart state message  =
        encryptPart state message
        |> Result.failOnError "Part encryption failed."
    header, partsWithType |> Seq.mapFold encryptPart state |> fst
let decrypt key (header, (parts : _ seq)) =
    State.MakeDecryptionState(key, header)
    |> Result.map (fun state -> seq {
        use enumerator = parts.GetEnumerator()
        let rec run state cipherText = seq {
            let result = decryptPart state cipherText
            match result with
            | Ok (plainText, Final, _) -> yield Ok plainText
            | Ok (plainText, _, state) ->
                yield Ok plainText
                if enumerator.MoveNext()
                then yield! run state enumerator.Current
                else failwith "Unanticipated stream end"
            | Error x -> yield Error x
        }
        let empty = enumerator.MoveNext() |> not
        if not empty then yield! run state enumerator.Current
    })

let alice = Key.GenerateDisposable()
let encryptWithFixture x = encrypt alice x
let decryptWithFixture x =
    decrypt alice x
    |> Result.failOnError "Bad header"
    |> List.ofSeq
    |> Result.sequence
let getKeyCopy (state : State) = state.State.k |> Array.copy

[<Tests>]
let tests =
    testList "StreamEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            stream
            |> encryptWithFixture
            |> decryptWithFixture
            =! Ok stream
        yield testCase "Decrypt fails with missing part" <| fun () ->
            let encrypted =
                let h, c = encryptWithFixture stream
                h, c |> Seq.skip 1
            decryptWithFixture encrypted =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with modified part" <| fun () ->
            let encrypted =
                let h, c = encryptWithFixture stream
                let c = List.ofSeq c
                let bytes = List.head c
                bytes.[0] <- if bytes.[0] = 0uy then 1uy else 0uy
                h, c
            decryptWithFixture encrypted =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong header" <| fun () ->
            let anotherHeader, _ =
                State.MakeEncryptionState(alice)
                |> Result.failOnError "Encryption state generation failed"
            let encrypted =
                let _, c = encrypt alice stream
                anotherHeader, c
            decryptWithFixture encrypted =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            encryptWithFixture stream
            |> decrypt (Key.GenerateDisposable())
            |> Result.failOnError "Bad header"
            |> List.ofSeq
            |> Result.sequence
            =! (Error <| SodiumError -1)
        yield testCase "Key is not modified after encrypting message" <| fun () ->
            let _, initialState = makeEncryptionState alice
            let initialStateKey = getKeyCopy initialState

            let nextState =
                encryptPart initialState ([|1uy; 2uy; 3uy|], Message)
                >>- snd
                |> Result.failOnError "Encryption failed"

            nextState.State.k =! initialStateKey
        yield testCase "Key is not modified after encrypting push" <| fun () ->
            let _, initialState = makeEncryptionState alice
            let initialStateKey = getKeyCopy initialState

            let nextState =
                encryptPart initialState ([|1uy; 2uy; 3uy|], Push)
                >>- snd
                |> Result.failOnError "Encryption failed"

            nextState.State.k =! initialStateKey
        yield testCase "Key is modified after encrypting rekey" <| fun () ->
            let _, initialState = makeEncryptionState alice
            let initialStateKey = getKeyCopy initialState

            let nextState =
                encryptPart initialState ([|1uy; 2uy; 3uy|], Rekey)
                >>- snd
                |> Result.failOnError "Encryption failed"

            nextState.State.k <>! initialStateKey
        yield testCase "Key is modified after encrypting final" <| fun () ->
            let _, initialState = makeEncryptionState alice
            let initialStateKey = getKeyCopy initialState

            let nextState =
                encryptPart initialState ([|1uy; 2uy; 3uy|], Final)
                >>- snd
                |> Result.failOnError "Encryption failed"

            nextState.State.k <>! initialStateKey
        yield testCase "Key is copied after encryption" <| fun () ->
            let _, initialState = makeEncryptionState alice
            let initialStateKey = getKeyCopy initialState

            let nextState =
                encryptPart initialState ([|1uy; 2uy; 3uy|], Message)
                >>- snd
                |> Result.failOnError "Encryption failed"
            let nextStateKey = getKeyCopy nextState

            initialState.Dispose()

            initialStateKey <>! zeroKey
            initialState.State.k =! zeroKey
            initialStateKey =! nextStateKey
            nextState.State.k =! nextStateKey
        yield testCase "Key is copied after decryption" <| fun () ->
            let header, c =
                let header, initialState = makeEncryptionState alice
                encryptPart initialState ([|1uy; 2uy; 3uy|], Message)
                >>- fun (c, _) -> header, c
                |> Result.failOnError "Encryption failed"

            let initialState =
                State.MakeDecryptionState(alice, header)
                |> Result.failOnError "Decryption state generation failed"
            let initialStateKey = getKeyCopy initialState

            let nextState =
                decryptPart initialState c
                >>- (fun (_, _, s) -> s)
                |> Result.failOnError "Decryption failed"
            let nextStateKey = getKeyCopy nextState

            initialState.Dispose()

            initialStateKey <>! zeroKey
            initialState.State.k =! zeroKey
            initialStateKey =! nextStateKey
            nextState.State.k =! nextStateKey
    ]
