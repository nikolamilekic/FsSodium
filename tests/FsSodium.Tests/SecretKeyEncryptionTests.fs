module FsSodium.Tests.SecretKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium

let alice = SecretKeyEncryption.Key.Generate()
let eve = SecretKeyEncryption.Key.Generate()

let generateNonce = SecretKeyEncryption.Nonce.Generate
let encrypt a b =
    SecretKeyEncryption.encrypt a b >> Result.failOnError "Encryption failed"
let decrypt = SecretKeyEncryption.decrypt

[<Tests>]
let tests =
    testList "SecretKeyEncryption" [
        testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt alice nonce plainText
            |> fun c -> decrypt alice nonce c
            =! Ok plainText
        testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            let cipherText =
                encrypt alice nonce plainText

            cipherText[0] <- if cipherText[0] = 0uy then 1uy else 0uy
            decrypt alice nonce cipherText
            =! (Error <| SodiumError -1)
        testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            encrypt alice nonce1 plainText
            |> fun c -> decrypt alice nonce2 c
            =! (Error <| SodiumError -1)
        testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt alice nonce plainText
            |> fun c -> decrypt eve nonce c
            =! (Error <| SodiumError -1)
        testCase "Known result" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce =
                "5f6856b66f2009f48d6a124ccb15b59af13011343e5d6928"
                |> Parsing.parseByteArrayFromHexString
                |> SecretKeyEncryption.Nonce.Import
                |> Result.failOnError "Failed to import nonce"
            let secretKey =
                "b5bfc28aef3166e87bfb3c5d7d17efb80b21c6e0d6ac100e74465b48351bf80f"
                |> Parsing.parseByteArrayFromHexString
                |> SecretKeyEncryption.Key.Import
                |> Result.failOnError "Failed to import secret key"
            encrypt secretKey nonce plainText
            |> Parsing.byteArrayToHexString
            =! "bef4b3c1102bf613a1c2688834fb41d63ec203"
    ]
