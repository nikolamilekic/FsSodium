module FsSodium.Tests.StreamEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsSodium

open StreamEncryption

do Sodium.initialize()

let stream =
    Seq.init 10 byte
    |> Seq.chunkBySize 3
    |> Seq.toList

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
    let header, state = State.MakeEncryptionState key
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
                else yield Error ()
            | Ok (plainText, Last, _) -> yield Ok plainText
            | _ -> yield Error ()
        }
        let empty = enumerator.MoveNext() |> not
        if not empty then yield! run state enumerator.Current
    })

let alice = Key.GenerateDisposable()

[<Tests>]
let tests =
    testList "StreamEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let decrypted =
                encrypt alice stream
                |> decrypt alice
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
                |> Result.failOnError "Decryption failed"
            decrypted =! stream
        yield testCase "Decrypt fails with missing part" <| fun () ->
            let encrypted =
                let h, c = encrypt alice stream
                h, c |> Seq.skip 1
            let result =
                decrypt alice encrypted
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
            result =! Error()
        yield testCase "Decrypt fails with modified part" <| fun () ->
            let encrypted =
                let h, c = encrypt alice stream
                let c = List.ofSeq c
                let bytes = List.head c
                bytes.[0] <- if bytes.[0] = 0uy then 1uy else 0uy
                h, c
            let result =
                decrypt alice encrypted
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
            result =! Error()
        yield testCase "Decrypt fails with wrong header" <| fun () ->
            let anotherHeader, _ = State.MakeEncryptionState(alice)
            let encrypted =
                let _, c = encrypt alice stream
                anotherHeader, c
            let result =
                decrypt alice encrypted
                |> Result.bind (List.ofSeq >> Result.sequence)
            result =! Error()
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let decrypted =
                encrypt alice stream
                |> decrypt (Key.GenerateDisposable())
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
            decrypted =! Error ()
    ]
