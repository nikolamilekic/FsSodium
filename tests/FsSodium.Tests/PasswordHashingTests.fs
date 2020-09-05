module FsSodium.Tests.PasswordHashingTests

open System.Text
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
        testCase "Hashing with same parameters leads to same results" <| fun () ->
            let password = generateRandomPassword()
            let salt = generateSalt()
            hashWithFixture salt password =! hashWithFixture salt password
        testCase "Hashing with different parameters leads to different results" <| fun () ->
            let password = generateRandomPassword()
            let salt1 = generateSalt()
            let salt2 = generateSalt()
            hashWithFixture salt1 password <>! hashWithFixture salt2 password
        testCase "Known result" <| fun () ->
            let salt =
                "aed2374479934c46987619d789425c02"
                |> Parsing.parseByteArrayFromHexString
                |> PasswordHashing.Salt.Import
                |> Result.failOnError "Failed to import salt"
            let password =
                "test"
                |> Encoding.UTF8.GetBytes
                |> PasswordHashing.Password.Import
                |> Result.failOnError "Failed to import password"
            hashWithFixture salt password
            |> Parsing.byteArrayToHexString =! "79332248223f77a230da03258b9b1f82"
    ]
