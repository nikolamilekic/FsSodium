module FsSodium.Tests.SecretKeyEncryptionTests

open Expecto
open Swensen.Unquote

open FsSodium
open SecretKeyEncryption

do Sodium.initialize()

[<Tests>]
let tests =
    testList "SecretKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let key = generateKey()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce = generateNonce()
            encrypt key (nonce, plainText)
            |> decrypt key
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let key = generateKey()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce = generateNonce()
            let { CipherTextBytes = cipherTextBytes } as cipherText =
                encrypt key (nonce, plainText)
            cipherTextBytes.[0] <- if cipherTextBytes.[0] = 0uy then 1uy else 0uy
            decrypt key cipherText =! Error()
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let key = generateKey()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            let cipherText = encrypt key (nonce1, plainText)
            { cipherText with Nonce = nonce2 }
            |> decrypt key
            =! Error()
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let key = generateKey()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce = generateNonce()
            let eveKey = generateKey()
            encrypt key (nonce, plainText)
            |> decrypt eveKey
            =! Error()
    ]
