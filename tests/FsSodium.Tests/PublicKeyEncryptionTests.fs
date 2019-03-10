module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open PublicKeyEncryption

do Sodium.initialize()

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyEncryption" [
        yield testCase "Roundtrip works" <| fun () ->
            let keyPair = generateKeyPair()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce = generateNonce()
            uncurry encrypt keyPair (nonce, plainText)
            |> uncurry decrypt keyPair
            =! Ok plainText
        yield testCase "Alice and bob roundtrip works" <| fun () ->
            let alice = generateKeyPair()
            let bob = generateKeyPair()
            let nonce = generateNonce()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            encrypt (fst alice) (snd bob) (nonce, plainText)
            |> decrypt (fst bob) (snd alice)
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let keyPair = generateKeyPair()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce = generateNonce()
            let { CipherTextBytes = cipherTextBytes } as cipherText =
                uncurry encrypt keyPair (nonce, plainText)
            cipherTextBytes.[0] <- if cipherTextBytes.[0] = 0uy then 1uy else 0uy
            uncurry decrypt keyPair cipherText =! Error()
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let keyPair = generateKeyPair()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            let cipherText = uncurry encrypt keyPair (nonce1, plainText)
            { cipherText with Nonce = nonce2 }
            |> uncurry decrypt keyPair
            =! Error()
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let keyPair = generateKeyPair()
            let plainText = [|1uy; 2uy; 3uy|] |> PlainText
            let nonce = generateNonce()
            let secretKeyEve, _ = generateKeyPair()
            uncurry encrypt keyPair (nonce, plainText)
            |> decrypt secretKeyEve (snd keyPair)
            =! Error()
    ]
