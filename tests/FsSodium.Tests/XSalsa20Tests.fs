module FsSodium.Tests.XSalsa20Tests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium

let alice = XSalsa20.Key.Generate()
let eve = XSalsa20.Key.Generate()

let generateNonce = XSalsa20.Nonce.Generate
let encrypt a b =
    XSalsa20.encryptDecrypt a b >> Result.failOnError "Encryption failed"
let decrypt a = XSalsa20.encryptDecrypt a

[<Tests>]
let tests =
    testList "XSalsa20" [
        testCase "Roundtrip works" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce = generateNonce()
            encrypt alice nonce plainText
            |> fun c -> decrypt alice nonce c
            =! Ok plainText
        testCase "Known result" <| fun () ->
            let plainText = [|1uy; 2uy; 3uy|]
            let nonce =
                "5f6856b66f2009f48d6a124ccb15b59af13011343e5d6928"
                |> Parsing.parseByteArrayFromHexString
                |> XSalsa20.Nonce.Import
                |> Result.failOnError "Failed to import nonce"
            let secretKey =
                "b5bfc28aef3166e87bfb3c5d7d17efb80b21c6e0d6ac100e74465b48351bf80f"
                |> Parsing.parseByteArrayFromHexString
                |> XSalsa20.Key.Import
                |> Result.failOnError "Failed to import secret key"
            encrypt secretKey nonce plainText
            |> Parsing.byteArrayToHexString
            =! "ee32f3"
    ]
