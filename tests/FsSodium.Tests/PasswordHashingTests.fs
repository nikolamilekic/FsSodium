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
        yield testCase "Hashing with same parameters leads to same results" <| fun () ->
            result {
                let! operations = NumberOfOperations.Create 1
                let! memory = MemoryLimit.Create 8192
                let parameters = {
                    NumberOfOperations = operations
                    MemoryLimit = memory
                    Algorithm = Algorithm.Default
                    Salt = Salt.Generate()
                }
                let! keyLength = KeyLength.Create 16
                let! password = Random.bytes 16 |> Password.CreateDisposable
                let go () = hashPassword keyLength parameters password
                let! first = go()
                let! second = go()
                first =! second
                return ()
            }
            |> Result.failOnError "Passwords hashes don't match"

        yield testCase "Hasing with different parameters leads to different results" <| fun () ->
            result {
                let! password = Random.bytes 16 |> Password.CreateDisposable
                let go () = result {
                    let! operations = NumberOfOperations.Create 1
                    let! memory = MemoryLimit.Create 8192
                    let parameters = {
                        NumberOfOperations = operations
                        MemoryLimit = memory
                        Algorithm = Algorithm.Default
                        Salt = Salt.Generate()
                    }
                    let! keyLength = KeyLength.Create 16
                    return! hashPassword keyLength parameters password
                }
                let! first = go()
                let! second = go()
                first <>! second
                return ()
            }
            |> Result.failOnError "Passwords hashes don't match"
    ]
