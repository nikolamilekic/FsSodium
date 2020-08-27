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
        testCase "Alice to herself roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            PublicKeyEncryption.encrypt (fst alice) (snd alice) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst alice) (snd alice) (nonce, c)
            =! Ok plainText
        testCase "Alice and bob roundtrip works" <| fun () ->
            let nonce = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst bob) (snd alice) (nonce, c)
            =! Ok plainText
        testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                c.[0] <- if c.[0] = 0uy then 1uy else 0uy
                PublicKeyEncryption.decrypt (fst bob) (snd alice) (nonce, c)
            =! (Error <| SodiumError -1)
        testCase "Decrypt fails with modified nonce" <| fun () ->
            let nonce1 = Nonce.Generate()
            let nonce2 = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce1, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst bob) (snd alice) (nonce2, c)
            =! (Error <| SodiumError -1)
        testCase "Decrypt fails with wrong key" <| fun () ->
            let nonce = Nonce.Generate()
            let plainText = [|1uy; 2uy; 3uy|]
            PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                PublicKeyEncryption.decrypt (fst eve) (snd alice) (nonce, c)
            =! (Error <| SodiumError -1)
        testCase "Public key computation from secret key works" <| fun () ->
            PublicKey.FromSecretKey (fst alice) =! Ok (snd alice)
            PublicKey.FromSecretKey (fst bob) =! Ok (snd bob)
            PublicKey.FromSecretKey (fst eve) =! Ok (snd eve)
        testCase "Roundtrip with precomputed key works" <| fun _ ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let cipherText =
                let sharedKey =
                    PublicKeyEncryption.precomputeSharedKey (fst alice) (snd bob)
                    |> Result.failOnError "Could not precompute shared key at encryption time"
                PublicKeyEncryption.encryptWithSharedKey sharedKey (nonce, plainText)
                |> Result.failOnError "Encryption failed"
            let decrypted =
                let sharedKey =
                    PublicKeyEncryption.precomputeSharedKey (fst bob) (snd alice)
                    |> Result.failOnError "Could not precompute shared key at encryption time"
                PublicKeyEncryption.decryptWithSharedKey sharedKey (nonce, cipherText)
            decrypted =! Ok plainText
        testCase "Roundtrip with precomputed key at decryption time only works" <| fun _ ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = Nonce.Generate()
            let cipherText =
                PublicKeyEncryption.encrypt (fst alice) (snd bob) (nonce, plainText)
                |> Result.failOnError "Encryption failed"
            let decrypted =
                let sharedKey =
                    PublicKeyEncryption.precomputeSharedKey (fst bob) (snd alice)
                    |> Result.failOnError "Could not precompute shared key at encryption time"
                PublicKeyEncryption.decryptWithSharedKey sharedKey (nonce, cipherText)
            decrypted =! Ok plainText
    ]
