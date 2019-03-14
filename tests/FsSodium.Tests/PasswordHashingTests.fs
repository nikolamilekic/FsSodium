module FsSodium.Tests.PasswordHashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsSodium
open FsSodium.PasswordHashing

do initializeSodium()

let operations =
    NumberOfOperations.Create 1
    |> Result.failOnError "Number of operations creation failed"
let memory =
    MemoryLimit.Create 8192 |> Result.failOnError "Memory limit creation failed"
let keyLength =
    KeyLength.Create 16 |> Result.failOnError "Key length creation failed"
let hashWithFixture salt password =
    let parameters = {
        NumberOfOperations = operations
        MemoryLimit = memory
        Algorithm = Algorithm.Default
        Salt = salt
    }
    hashPassword keyLength parameters password
    |> Result.failOnError "Hashing failed"
let generateRandomPassword() =
    Random.bytes 16
    |> Password.CreateDisposable
    |> Result.failOnError "Password generation failed"

[<Tests>]
let passwordHashingTests =
    testList "PasswordHashing" [
        yield testCase "Hashing with same parameters leads to same results" <| fun () ->
            let password = generateRandomPassword()
            let salt = Salt.Generate()
            hashWithFixture salt password =! hashWithFixture salt password
        yield testCase "Hashing with different parameters leads to different results" <| fun () ->
            let password = generateRandomPassword()
            let salt1 = Salt.Generate()
            let salt2 = Salt.Generate()
            hashWithFixture salt1 password <>! hashWithFixture salt2 password
    ]
