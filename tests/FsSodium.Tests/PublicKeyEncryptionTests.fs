module FsSodium.Tests.PublicKeyEncryptionTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium

let generateKey =
    PublicKeyEncryption.SecretKey.Generate >> Result.failOnError "Key generation failed"

let alice = generateKey()
let bob = generateKey()
let eve = generateKey()

let generateNonce () = PublicKeyEncryption.Nonce.Generate()
let encrypt a b =
    PublicKeyEncryption.encrypt a b
    >> Result.failOnError "Encryption failed"
let encryptWithSharedSecret a =
    PublicKeyEncryption.encryptWithSharedSecret a
    >> Result.failOnError "Encryption failed"
let decrypt = PublicKeyEncryption.decrypt
let decryptWithSharedSecret = PublicKeyEncryption.decryptWithSharedSecret
let fromSecretKey = PublicKeyEncryption.PublicKey.FromSecretKey
let precomputeSharedSecret a =
    PublicKeyEncryption.SharedSecret.Precompute a
    >> Result.failOnError "Could not precompute shared secret"

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyEncryption" [
        testCase "Alice to herself roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt (fst alice) (snd alice) (nonce, plainText)
            |> fun c -> decrypt (fst alice) (snd alice) (nonce, c)
            =! Ok plainText
        testCase "Alice and bob roundtrip works" <| fun () ->
            let nonce = generateNonce()
            let plainText = [|1uy; 2uy; 3uy|]
            encrypt (fst alice) (snd bob) (nonce, plainText)
            |> fun c -> decrypt (fst bob) (snd alice) (nonce, c)
            =! Ok plainText
        testCase "Decrypt fails with modified cipher text" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt (fst alice) (snd bob) (nonce, plainText)
            |> fun c ->
                c.[0] <- if c.[0] = 0uy then 1uy else 0uy
                decrypt (fst bob) (snd alice) (nonce, c)
            =! (Error <| SodiumError -1)
        testCase "Decrypt fails with modified nonce" <| fun () ->
            let nonce1 = generateNonce()
            let nonce2 = generateNonce()
            let plainText = [|1uy; 2uy; 3uy|]
            encrypt (fst alice) (snd bob) (nonce1, plainText)
            |> fun c ->
                decrypt (fst bob) (snd alice) (nonce2, c)
            =! (Error <| SodiumError -1)
        testCase "Decrypt fails with wrong key" <| fun () ->
            let nonce = generateNonce()
            let plainText = [|1uy; 2uy; 3uy|]
            encrypt (fst alice) (snd bob) (nonce, plainText)
            |> fun c -> decrypt (fst eve) (snd alice) (nonce, c)
            =! (Error <| SodiumError -1)
        testCase "Public key computation from secret key works" <| fun () ->
            fromSecretKey (fst alice) =! Ok (snd alice)
            fromSecretKey (fst bob) =! Ok (snd bob)
            fromSecretKey (fst eve) =! Ok (snd eve)
        testCase "Roundtrip with precomputed secret works" <| fun _ ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            let cipherText =
                let sharedSecret = precomputeSharedSecret (fst alice) (snd bob)
                encryptWithSharedSecret sharedSecret (nonce, plainText)
            let decrypted =
                let sharedSecret = precomputeSharedSecret (fst bob) (snd alice)
                decryptWithSharedSecret sharedSecret (nonce, cipherText)
            decrypted =! Ok plainText
        testCase "Roundtrip with precomputed key at decryption time only works" <| fun _ ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            let cipherText = encrypt (fst alice) (snd bob) (nonce, plainText)
            let decrypted =
                let sharedSecret = precomputeSharedSecret (fst bob) (snd alice)
                decryptWithSharedSecret sharedSecret (nonce, cipherText)
            decrypted =! Ok plainText
        testCase "Roundtrip with precomputed key at encryption time only works" <| fun _ ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            let cipherText =
                let sharedSecret = precomputeSharedSecret (fst alice) (snd bob)
                encryptWithSharedSecret sharedSecret (nonce, plainText)
            let decrypted = decrypt (fst bob) (snd alice) (nonce, cipherText)
            decrypted =! Ok plainText
    ]
