module FsSodium.Tests.SecretKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Chessie.ErrorHandling
open FsSodium
open SecretKeyEncryption

do Sodium.initialize()

let alice = Key.GenerateDisposable()
let eve = Key.GenerateDisposable()

[<Tests>]
let tests =
    testList "SecretKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encrypt alice nonce plainText
            |> decrypt alice nonce
            =! ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let cipherText = encrypt alice nonce plainText
            cipherText.[0] <- if cipherText.[0] = 0uy then 1uy else 0uy
            decrypt alice nonce cipherText |> failed =! true
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = Nonce.Generate()
            let nonce2 = Nonce.Generate()
            encrypt alice nonce1 plainText
            |> decrypt alice nonce2
            |> failed =! true
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encrypt alice nonce plainText
            |> decrypt eve nonce
            |> failed =! true
    ]
