module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open PublicKeyEncryption

do Sodium.initialize()

let generateKeyPair = generateKeyPair
                      >> Result.failOnError "generateKeyPair failed"
let secretKey, publicKey = generateKeyPair()

let encryptWithFixture = encrypt secretKey publicKey
                         >> Result.failOnError "encrypt failed"
let decryptWithFixture = decrypt secretKey publicKey
                         >> Result.failOnError "decrypt failed"

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce = generateNonce()
            encryptWithFixture (nonce, plainText)
            |> decryptWithFixture
            =! plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce = generateNonce()
            let { CipherTextBytes = cipherTextBytes } as cipherText =
                encryptWithFixture (nonce, plainText)
            cipherTextBytes.[0] <- cipherTextBytes.[1]
            decrypt secretKey publicKey cipherText =! Error()
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            let cipherText = encryptWithFixture (nonce1, plainText)
            { cipherText with Nonce = nonce2 }
            |> decrypt secretKey publicKey
            =! Error()
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce = generateNonce()
            let secretKeyEve, _ = generateKeyPair()
            encryptWithFixture (nonce, plainText)
            |> decrypt secretKeyEve publicKey
            =! Error()
    ]
