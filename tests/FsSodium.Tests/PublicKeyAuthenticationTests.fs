module FsSodium.Tests.PublicKeyAuthenticationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium
open FsSodium.PublicKeyAuthentication

do initializeSodium()

let secretKey, publicKey =
    SecretKey.Generate() |> Result.failOnError "Key generation failed"

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyAuthenticaion" [
        yield testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac =
                PublicKeyAuthentication.sign secretKey plainText
                |> Result.failOnError "Signing failed"
            PublicKeyAuthentication.verify publicKey (plainText, mac) =! Ok ()
        yield testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let rawMac =
                PublicKeyAuthentication.sign secretKey plainText
                |>> fun m -> m.Get
                |> Result.failOnError "Signing failed"
            rawMac.[0] <- if rawMac.[0] = 0uy then 1uy else 0uy
            let mac = Mac.Import rawMac |> Result.failOnError "Could not reimport mac"
            PublicKeyAuthentication.verify publicKey (plainText, mac)
            =! (Error <| SodiumError -1)
        yield testCase "Verify fails for modified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac =
                PublicKeyAuthentication.sign secretKey plainText
                |> Result.failOnError "Signing failed"
            plainText.[0] <- 0uy
            PublicKeyAuthentication.verify publicKey (plainText, mac)
            =! (Error <| SodiumError -1)
        yield testCase "Verify fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac =
                PublicKeyAuthentication.sign secretKey plainText
                |> Result.failOnError "Signing failed"
            let pkEve =
                SecretKey.Generate() |>> snd
                |> Result.failOnError "Eve key generation failed"
            PublicKeyAuthentication.verify pkEve (plainText, mac)
            =! (Error <| SodiumError -1)
        yield testCase "Public key computation from secret key works" <| fun () ->
            PublicKey.FromSecretKey secretKey =! Ok publicKey
    ]
