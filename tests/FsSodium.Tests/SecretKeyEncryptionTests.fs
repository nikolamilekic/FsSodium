module FsSodium.Tests.SecretKeyEncryptionTests

open Expecto
open Swensen.Unquote
open FsSodium
open SecretKeyEncryption
open Milekic.YoLo

do initializeSodium()

let alice = Key.Generate()
let encryptWithFixture =
    uncurry <| encrypt alice
    >> Result.failOnError "Encryption failed"
    |> curry
let decryptWithFixture = decrypt alice

[<Tests>]
let tests =
    testList "SecretKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encryptWithFixture nonce plainText
            |> decryptWithFixture nonce
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let cipherText = encryptWithFixture nonce plainText
            cipherText.[0] <- if cipherText.[0] = 0uy then 1uy else 0uy
            decryptWithFixture nonce cipherText =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = Nonce.Generate()
            let nonce2 = Nonce.Generate()
            encryptWithFixture nonce1 plainText
            |> decryptWithFixture nonce2
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encryptWithFixture nonce plainText
            |> decrypt (Key.Generate()) nonce
            =! (Error <| SodiumError -1)
    ]
