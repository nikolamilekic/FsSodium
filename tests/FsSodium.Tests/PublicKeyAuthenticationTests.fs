module FsSodium.Tests.PublicKeyAuthenticationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open Milekic.YoLo.Result.Operators
open FsSodium
open PublicKeyAuthentication

do initializeSodium()

let secretKey, publicKey =
    SecretKey.Generate() |> Result.failOnError "Key generation failed"
let signWithFixture = sign secretKey >> Result.failOnError "Signing failed"
let verifyWithFixture = verify publicKey

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyAuthenticaion" [
        yield testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            verifyWithFixture plainText mac =! Ok ()
        yield testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = (signWithFixture plainText).Value
            mac.[0] <- if mac.[0] = 0uy then 1uy else 0uy
            let mac = Mac.Validate mac |> Result.failOnError "Bad mac"
            verifyWithFixture plainText mac =! (Error <| SodiumError -1)
        yield testCase "Verify fails for modified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            plainText.[0] <- if plainText.[0] = 0uy then 1uy else 0uy
            verifyWithFixture plainText mac =! (Error <| SodiumError -1)
        yield testCase "Verify fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            let pkEve =
                SecretKey.Generate() >>- snd
                |> Result.failOnError "Eve key generation failed"
            verify pkEve plainText mac =! (Error <| SodiumError -1)
        yield testCase "Public key computation from secret key works" <| fun () ->
            PublicKey.Compute secretKey =! Ok publicKey
    ]
