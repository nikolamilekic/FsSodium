module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open PublicKeyEncryption

do Sodium.initialize()

let generateKeyPair = generateKeyPair
                      >> Result.failOnError "generateKeyPair failed"
let publicKey, secretKey = generateKeyPair()

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
            let cipherText = encryptWithFixture (nonce, plainText)
            let decrypted = decryptWithFixture (nonce, cipherText)
            decrypted =! plainText
        yield testCase "Decrypt fails for modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce = generateNonce()
            let (CipherTextBytes cipherTextBytes) as cipherText =
                encryptWithFixture (nonce, plainText)
            cipherTextBytes.[0] <- cipherTextBytes.[1]
            decrypt secretKey publicKey (nonce, cipherText) =! Error()
        yield testCase "Decrypt fails for modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            let cipherText = encryptWithFixture (nonce1, plainText)
            decrypt secretKey publicKey (nonce2, cipherText) =! Error()
        yield testCase "Decrypt fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let nonce = generateNonce()
            let cipherText = encryptWithFixture (nonce, plainText)
            let _, secretKeyEve = generateKeyPair()
            decrypt secretKeyEve publicKey (nonce, cipherText) =! Error()
    ]
