module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsSodium
open PublicKeyEncryption

do initializeSodium()

let generateKey =
    SecretKey.GenerateDisposable >> Result.failOnError "Key generation failed"

let alice = generateKey()
let bob = generateKey()
let eve = generateKey()
let encryptWithFixture =
    uncurry <| encrypt alice bob.PublicKey
    >> Result.failOnError "Encryption failed"
    |> curry
let decryptWithFixture = decrypt bob alice.PublicKey

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyEncryption" [
        yield testCase "Alice to herself roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encrypt alice alice.PublicKey nonce plainText
            |> Result.failOnError "Encryption failed"
            |> decrypt alice alice.PublicKey nonce
            =! Ok plainText
        yield testCase "Alice and bob roundtrip works" <| fun () ->
            let nonce = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
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
            let cipherText = encryptWithFixture nonce1 plainText
            decryptWithFixture nonce2 cipherText =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encryptWithFixture nonce plainText
            |> decrypt eve alice.PublicKey nonce
            =! (Error <| SodiumError -1)
    ]
