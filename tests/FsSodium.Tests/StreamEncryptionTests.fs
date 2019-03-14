module FsSodium.Tests.StreamEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsSodium

open StreamEncryption

do initializeSodium()

let stream = Seq.init 10 byte |> Seq.chunkBySize 3 |> Seq.toList

let encrypt key (parts : _ seq) =
    let partsWithType = seq {
        use enumerator = parts.GetEnumerator()
        let rec run current = seq {
            let currentIsLast = enumerator.MoveNext() |> not
            if currentIsLast then yield current, Last
            else yield current, NotLast; yield! run enumerator.Current
        }
        let empty = enumerator.MoveNext() |> not
        if not empty then yield! run enumerator.Current
    }
    let header, state =
        State.MakeEncryptionState key
        |> Result.failOnError "Encryption state generation failed"
    let encryptPart state message  =
        let tag, result = encryptPart state message
        tag, result |> Result.failOnError "Part encryption failed."
    header, partsWithType |> Seq.mapFold encryptPart state |> fst
let decrypt key (header, (parts : _ seq)) =
    State.MakeDecryptionState(key, header)
    |> Result.map (fun state -> seq {
        use enumerator = parts.GetEnumerator()
        let rec run state cipherText = seq {
            let result = decryptPart state cipherText
            match result with
            | Ok (plainText, NotLast, state) ->
                yield Ok plainText
                if enumerator.MoveNext()
                then yield! run state enumerator.Current
                else failwith "Unanticipated stream end"
            | Ok (plainText, Last, _) -> yield Ok plainText
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
    ]
