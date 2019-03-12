module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsSodium
open PublicKeyEncryption

do Sodium.initialize()

let alice = SecretKey.GenerateDisposable()
let bob = SecretKey.GenerateDisposable()
let eve = SecretKey.GenerateDisposable()

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encrypt alice alice.PublicKey nonce plainText
            |> decrypt alice alice.PublicKey nonce
            =! Ok plainText
        yield testCase "Alice and bob roundtrip works" <| fun () ->
            let nonce = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            encrypt alice bob.PublicKey nonce plainText
            |> decrypt bob alice.PublicKey nonce
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let cipherText =
                encrypt alice alice.PublicKey nonce plainText
            cipherText.[0] <- if cipherText.[0] = 0uy then 1uy else 0uy
            decrypt alice alice.PublicKey nonce cipherText |> Result.isError
            =! true
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = Nonce.Generate()
            let nonce2 = Nonce.Generate()
            let cipherText = encrypt alice alice.PublicKey nonce1 plainText
            decrypt alice alice.PublicKey nonce2 cipherText |> Result.isError
            =! true
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            encrypt alice bob.PublicKey nonce plainText
            |> decrypt eve alice.PublicKey nonce
            |> Result.isError
            =! true
    ]
