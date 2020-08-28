module FsSodium.Tests.PasswordHashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FsSodium

let operations =
    PasswordHashing.NumberOfOperations.Custom 1UL
    |> Result.failOnError "Number of operations creation failed"
let memory =
    PasswordHashing.MemoryLimit.Custom 8192u |> Result.failOnError "Memory limit creation failed"
let keyLength =
    PasswordHashing.KeyLength.Validate 16 |> Result.failOnError "Key length creation failed"
let hashWithFixture salt password =
    let parameters : PasswordHashing.HashPasswordParameters = {
        NumberOfOperations = operations
        MemoryLimit = memory
        Algorithm = PasswordHashing.Algorithm.Default
        Salt = salt
    }
    PasswordHashing.hashPassword keyLength parameters password
    |> Result.failOnError "Hashing failed"
let generateRandomPassword() =
    Random.bytes 16
    |> PasswordHashing.Password.Import
    |> Result.failOnError "Password generation failed"
let generateSalt() = PasswordHashing.Salt.Generate()

[<Tests>]
let passwordHashingTests =
    testList "PasswordHashing" [
        yield testCase "Hashing with same parameters leads to same results" <| fun () ->
            let password = generateRandomPassword()
            let salt = generateSalt()
            hashWithFixture salt password =! hashWithFixture salt password
        yield testCase "Hashing with different parameters leads to different results" <| fun () ->
            let password = generateRandomPassword()
            let salt1 = generateSalt()
            let salt2 = generateSalt()
            hashWithFixture salt1 password <>! hashWithFixture salt2 password
    ]
