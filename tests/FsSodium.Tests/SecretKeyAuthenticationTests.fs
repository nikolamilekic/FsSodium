module FsSodium.Tests.SecretKeyAuthenticationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium

let secretKey = SecretKeyAuthentication.Key.Generate()

let signWithFixture =
    SecretKeyAuthentication.sign secretKey
    >> Result.failOnError "Signing failed"

let verifyWithFixture = SecretKeyAuthentication.verify secretKey

[<Tests>]
let secretKeyAuthenticationTests =
    testList "SecretKeyAuthenticaion" [
        testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            verifyWithFixture mac plainText =! Ok ()
        testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let rawMac = (signWithFixture plainText).Get
            rawMac[0] <- if rawMac[0] = 0uy then 1uy else 0uy
            let mac =
                SecretKeyAuthentication.Mac.Import rawMac
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
            let pkEve = SecretKeyAuthentication.Key.Generate()
            SecretKeyAuthentication.verify pkEve mac plainText
            =! (Error <| SodiumError -1)
        testCase "Known result" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let secretKey =
                "63fa6ad24c39b7eecf3bae352d3c74658ccf4adf37af25227b8715aa42dbd07f"
                |> Parsing.parseByteArrayFromHexString
                |> SecretKeyAuthentication.Key.Import
                |> Result.failOnError "Failed to import key"
            SecretKeyAuthentication.sign secretKey plainText
            |> Result.failOnError "Signing failed"
            |> fun x -> x.Get |> Parsing.byteArrayToHexString
            =! "6a344c2ce1a7d3702f64470e1aa3e1fa70e0d297318a50e2528ac822dad6a415"
    ]
