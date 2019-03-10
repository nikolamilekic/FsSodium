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
    |> Seq.map PlainText
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
    let header, state = makeEncryptionState key
    header, partsWithType |> Seq.mapFold encryptPart state |> fst
let decrypt key (header, (parts : _ seq)) =
    makeDecryptionState key header
    |> Result.map (fun state -> seq {
        use enumerator = parts.GetEnumerator()
        let rec run state cipherText = seq {
            let result = decryptPart state cipherText
            match result with
            | Error () -> yield Error ()
            | Ok (plainText, NotLast, state) ->
                yield Ok plainText
                if enumerator.MoveNext()
                then yield! run state enumerator.Current
                else yield Error ()
            | Ok (plainText, Last, _) -> yield Ok plainText
        }
        let empty = enumerator.MoveNext() |> not
        if not empty then yield! run state enumerator.Current
    })

[<Tests>]
let tests =
    testList "StreamEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let key = generateKey()
            let decrypted =
                encrypt key stream
                |> decrypt key
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
                |> Result.failOnError "Decryption failed"
            decrypted =! stream
        yield testCase "Decrypt fails with missing part" <| fun () ->
            let key = generateKey()
            let encrypted =
                let h, c = encrypt key stream
                h, c |> Seq.skip 1
            let result =
                decrypt key encrypted
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
            result =! Error()
        yield testCase "Decrypt fails with modified part" <| fun () ->
            let key = generateKey()
            let encrypted =
                let h, c = encrypt key stream
                let c = List.ofSeq c
                let (CipherTextBytes bytes) = List.head c
                bytes.[0] <- if bytes.[0] = 0uy then 1uy else 0uy
                h, c
            let result =
                decrypt key encrypted
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
            result =! Error()
        yield testCase "Decrypt fails with modified header" <| fun () ->
            let key = generateKey()
            let encrypted =
                let HeaderBytes h, c = encrypt key stream
                h.[0] <- if h.[0] = 0uy then 1uy else 0uy
                HeaderBytes h, c
            let result =
                decrypt key encrypted
                |> Result.bind (List.ofSeq >> Result.sequence)
            result =! Error()
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let decrypted =
                encrypt (generateKey()) stream
                |> decrypt (generateKey())
                |> Result.failOnError "Bad header"
                |> List.ofSeq
                |> Result.sequence
            decrypted =! Error ()
    ]
