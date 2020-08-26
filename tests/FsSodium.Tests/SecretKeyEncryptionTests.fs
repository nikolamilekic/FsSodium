module FsSodium.Tests.SecretKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open FsSodium.SecretKeyEncryption

do initializeSodium()
let alice = Key.Generate()
let eve = Key.Generate()

[<Tests>]
let tests =
    testList "SecretKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            SecretKeyEncryption.encrypt alice (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c -> SecretKeyEncryption.decrypt alice (nonce, c)
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let cipherText =
                SecretKeyEncryption.encrypt alice (nonce, plainText)
                |> Result.failOnError "Encryption failed"
            cipherText.[0] <- if cipherText.[0] = 0uy then 1uy else 0uy
            SecretKeyEncryption.decrypt alice (nonce, cipherText)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = Nonce.Generate()
            let nonce2 = Nonce.Generate()
            SecretKeyEncryption.encrypt alice (nonce1, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c -> SecretKeyEncryption.decrypt alice (nonce2, c)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            SecretKeyEncryption.encrypt alice (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c -> SecretKeyEncryption.decrypt eve (nonce, c)
            =! (Error <| SodiumError -1)
    ]
