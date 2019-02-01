module FsSodium.Tests.PasswordHashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium
open FsSodium.PasswordHashing

do Sodium.initialize()

[<Tests>]
let passwordHashingTests =
    testList "PasswordHashing" [
        yield testCase "Hasing with same parameters leads to same results" <| fun () ->
            let parameters = {
                NumberOfOperations = 1
                Memory = 8192
                Algorithm = defaultAlgorithm
                Salt = generateSalt ()
            }
            let password = Random.bytes 16
            let go () =
                hashPassword 16 parameters password
                |> Result.failOnError "Hash could not be done"
                |> fun x -> x.Secret
            go() =! go()
        yield testCase "Hasing with different parameters leads to different results" <| fun () ->
            let password = Random.bytes 16
            let go () =
                let parameters = {
                    NumberOfOperations = 1
                    Memory = 8192
                    Algorithm = defaultAlgorithm
                    Salt = generateSalt ()
                }
                hashPassword 16 parameters password
                |> Result.failOnError "Hash could not be done"
                |> fun x -> x.Secret
            go() <>! go()
    ]
