module FsSodium.Tests.PublicKeyAuthenticationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open Chessie.ErrorHandling
open FsSodium
open PublicKeyAuthentication

do Sodium.initialize()

let secretKey = SecretKey.CreateDisposable()
let signWithFixture = sign secretKey
let verifyWithFixture =
    uncurry <| verify (secretKey.PublicKey) >> failed >> not
    |> curry

[<Tests>]
let publicKeyAuthenticationTests =
    testList "PublicKeyAuthenticaion" [
        yield testCase "Verify works for unmodified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            verifyWithFixture plainText mac =! true
        yield testCase "Verify fails for modified signature" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            mac.[0] <- if mac.[0] = 0uy then 1uy else 0uy
            verifyWithFixture plainText mac =! false
        yield testCase "Verify fails for modified message" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            plainText.[0] <- if plainText.[0] = 0uy then 1uy else 0uy
            verifyWithFixture plainText mac =! false
        yield testCase "Verify fails for wrong key" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let mac = signWithFixture plainText
            let pkEve = SecretKey.CreateDisposable().PublicKey
            verify pkEve plainText mac |> failed =! true
    ]
