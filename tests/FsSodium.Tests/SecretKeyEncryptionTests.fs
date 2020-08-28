module FsSodium.Tests.SecretKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium

do initializeSodium()
let alice = SecretKeyEncryption.Key.Generate()
let eve = SecretKeyEncryption.Key.Generate()

let generateNonce = SecretKeyEncryption.Nonce.Generate
let encrypt a =
    SecretKeyEncryption.encrypt a >> Result.failOnError "Encryption failed"
let decrypt = SecretKeyEncryption.decrypt

[<Tests>]
let tests =
    testList "SecretKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt alice (nonce, plainText)
            |> fun c -> decrypt alice (nonce, c)
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            let cipherText =
                encrypt alice (nonce, plainText)

            cipherText.[0] <- if cipherText.[0] = 0uy then 1uy else 0uy
            decrypt alice (nonce, cipherText)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            encrypt alice (nonce1, plainText)
            |> fun c -> decrypt alice (nonce2, c)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt alice (nonce, plainText)
            |> fun c -> decrypt eve (nonce, c)
            =! (Error <| SodiumError -1)
    ]
