module FsSodium.Tests.PasswordHashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open Chessie.ErrorHandling
open FsSodium
open FsSodium.PasswordHashing

do Sodium.initialize()

[<Tests>]
let passwordHashingTests =
    testList "PasswordHashing" [
        yield testCase "Hasing with same parameters leads to same results" <| fun () ->
            trial {
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
                first.Secret =! second.Secret
            }
            |> fun x -> trap <@ returnOrFail x @>

        yield testCase "Hasing with different parameters leads to different results" <| fun () ->
            trial {
                let! password = Random.bytes 16 |> Password.CreateDisposable
                let go () = trial {
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
                first.Secret <>! second.Secret
            }
            |> fun x -> trap <@ returnOrFail x @>
    ]
