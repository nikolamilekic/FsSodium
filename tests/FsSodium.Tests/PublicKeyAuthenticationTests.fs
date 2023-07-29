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
        testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            verifyWithFixture mac plainText =! Ok ()
        testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let rawMac = (signWithFixture plainText).Get
            rawMac[0] <- if rawMac[0] = 0uy then 1uy else 0uy
            let mac =
                PublicKeyAuthentication.Mac.Import rawMac
                |> Result.failOnError "Could not reimport mac"
            verifyWithFixture mac plainText
            =! (Error <| SodiumError -1)
        testCase "Verify fails for modified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture  plainText
            plainText[0] <- 0uy
            verifyWithFixture mac plainText
            =! (Error <| SodiumError -1)
        testCase "Verify fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            let pkEve =
                PublicKeyAuthentication.SecretKey.Generate() |>> snd
                |> Result.failOnError "Eve key generation failed"
            PublicKeyAuthentication.verify pkEve mac plainText
            =! (Error <| SodiumError -1)
        testCase "Public key computation from secret key works" <| fun () ->
            PublicKeyAuthentication.PublicKey.FromSecretKey secretKey
            =! Ok publicKey
        testCase "Known result" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let secretKey =
                "eb3bfcde6248db25d8ff637e82b91a003cea87e8d626ec94bb608a9d2916c276e8eb1fbf2c6f22a9118d2d1b8e0833f0cc9b508b2fa490ec2bb2d0f2003df197"
                |> Parsing.parseByteArrayFromHexString
                |> PublicKeyAuthentication.SecretKey.Import
                |> Result.failOnError "Key import failed"
            let mac =
                PublicKeyAuthentication.sign secretKey plainText
                |> Result.failOnError "Signing failed"
                |> fun x -> x.Get |> Parsing.byteArrayToHexString
            mac =! "a634c68eb7c0a262f519046047c6853142ac5d75c3b19df17727fdad8a8df1f913836787ae078311a9e57c7b1366db13c535d33d0508cc0aed397023239a0f09"
    ]
