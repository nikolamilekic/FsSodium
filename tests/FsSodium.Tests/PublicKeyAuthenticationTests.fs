module FsSodium.Tests.PublicKeyAuthenticationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open PublicKeyAuthentication

do Sodium.initialize()

let secretKey, publicKey = generateKeyPair()
let signWithFixture = sign secretKey
let verifyWithFixture = verify publicKey >> Result.failOnError "verify failed"

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyAuthenticaion" [
        yield testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let signedText = signWithFixture plainText
            let verifiedPlainText = verifyWithFixture signedText
            verifiedPlainText =! plainText
        yield testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let (SignedTextBytes signedBytes) as signedText =
                signWithFixture plainText
            signedBytes.[0] <- if signedBytes.[0] = 0uy then 1uy else 0uy
            verify publicKey signedText =! Error()
        yield testCase "Verify fails for modified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let (SignedTextBytes signedBytes) as signedText =
                signWithFixture plainText
            signedBytes.[Array.length signedBytes - 1] <- 4uy
            verify publicKey signedText =! Error()
        yield testCase "Verify fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|] |> PlainTextBytes
            let signedText = signWithFixture plainText
            let _, pkEve
             = generateKeyPair()
            verifyWithFixture signedText |> ignore
            verify pkEve signedText =! Error()
    ]
