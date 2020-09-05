module FsSodium.Tests.KeyDerivationTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium

let masterKey = KeyDerivation.MasterKey.Generate()
let context =
    KeyDerivation.Context.Validate "Testing "
    |> Result.failOnError "Failed to validate context"
let keyLength =
    KeyDerivation.KeyLength.Validate 32
    |> Result.failOnError "Failed to validate key length"
let derive id = KeyDerivation.deriveKey masterKey context id  keyLength

[<Tests>]
let passwordHashingTests =
    testList "Key derivation" [
        testCase "Deriving the same key twice yields same results" <| fun () ->
            let one = derive 1UL
            one |>> ignore =! Ok ()
            one =! derive 1UL
        testCase "Different id --> different keys" <| fun () ->
            derive 1UL <>! derive 2UL
        testCase "Known result" <| fun () ->
            let key =
                "63fa6ad24c39b7eecf3bae352d3c74658ccf4adf37af25227b8715aa42dbd07f"
                |> Parsing.parseByteArrayFromHexString
                |> KeyDerivation.MasterKey.Import
                |> Result.failOnError "Failed to import key"

            KeyDerivation.deriveKey key context 1UL keyLength
            |> Result.failOnError "Failed to derive key"
            |> Parsing.byteArrayToHexString =! "a6da13c86206f3ec4f44f80b954a94f5a5e33ad272f59f7b837874021ba0597b"
    ]
