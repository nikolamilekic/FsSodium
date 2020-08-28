module FsSodium.Tests.PublicKeyAuthenticationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium

let secretKey, publicKey =
    PublicKeyAuthentication.SecretKey.Generate() |> Result.failOnError "Key generation failed"

let signWithFixture =
    PublicKeyAuthentication.sign secretKey
    >> Result.failOnError "Signing failed"

let verifyWithFixture = PublicKeyAuthentication.verify publicKey

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyAuthenticaion" [
        yield testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            verifyWithFixture mac plainText =! Ok ()
        yield testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let rawMac = (signWithFixture plainText).Get
            rawMac.[0] <- if rawMac.[0] = 0uy then 1uy else 0uy
            let mac =
                PublicKeyAuthentication.Mac.Import rawMac
                |> Result.failOnError "Could not reimport mac"
            verifyWithFixture mac plainText
            =! (Error <| SodiumError -1)
        yield testCase "Verify fails for modified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture  plainText
            plainText.[0] <- 0uy
            verifyWithFixture mac plainText
            =! (Error <| SodiumError -1)
        yield testCase "Verify fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            let pkEve =
                PublicKeyAuthentication.SecretKey.Generate() |>> snd
                |> Result.failOnError "Eve key generation failed"
            PublicKeyAuthentication.verify pkEve mac plainText
            =! (Error <| SodiumError -1)
        yield testCase "Public key computation from secret key works" <| fun () ->
            PublicKeyAuthentication.PublicKey.FromSecretKey secretKey
            =! Ok publicKey
    ]
