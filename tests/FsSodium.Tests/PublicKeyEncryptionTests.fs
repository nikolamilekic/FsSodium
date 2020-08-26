module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open FsSodium.PublicKeyEncryption

do initializeSodium()

let generateKey =
    SecretKey.Generate >> Result.failOnError "Key generation failed"

let alice = generateKey()
let bob = generateKey()
let eve = generateKey()

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyEncryption" [
        yield testCase "Alice to herself roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            PublicKeyEncryption.encrypt (fst alice) (snd alice) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst alice) (snd alice) (nonce, c)
            =! Ok plainText
        yield testCase "Alice and bob roundtrip works" <| fun () ->
            let nonce = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst bob) (snd alice) (nonce, c)
            =! Ok plainText
        yield testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                c.[0] <- if c.[0] = 0uy then 1uy else 0uy
                PublicKeyEncryption.decrypt (fst bob) (snd alice) (nonce, c)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with modified nonce" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce1 = Nonce.Generate()
            let nonce2 = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce1, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst bob) (snd alice) (nonce2, c)
            =! (Error <| SodiumError -1)
        yield testCase "Decrypt fails with wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst eve) (snd alice) (nonce, c)
            =! (Error <| SodiumError -1)
        yield testCase "Public key computation from secret key works" <| fun () ->
            PublicKey.FromSecretKey (fst alice) =! Ok (snd alice)
            PublicKey.FromSecretKey (fst bob) =! Ok (snd bob)
            PublicKey.FromSecretKey (fst eve) =! Ok (snd eve)
    ]
