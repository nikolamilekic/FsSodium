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
        yield testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            verifyWithFixture mac plainText =! Ok ()
        yield testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let rawMac = (signWithFixture plainText).Get
            rawMac.[0] <- if rawMac.[0] = 0uy then 1uy else 0uy
            let mac =
                SecretKeyAuthentication.Mac.Import rawMac
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
            let pkEve = SecretKeyAuthentication.Key.Generate()
            SecretKeyAuthentication.verify pkEve mac plainText
            =! (Error <| SodiumError -1)
    ]
