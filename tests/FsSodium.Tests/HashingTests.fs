module FsSodium.Tests.HashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo

open FsSodium.Hashing

initializeSodium()

[<Tests>]
let hashingTests =
    testList "Hashing" [
        testList "All at once" [
            testCase "Same input produces same hash with no key" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                hash (Key.None) HashLength.recommended input
                =! hash (Key.None) HashLength.recommended input
            testCase "Same input produces same hash with key" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                let keyLength = KeyLength.recommended
                let key = Key.Generate keyLength
                hash key HashLength.recommended input
                =! hash key HashLength.recommended input
            testCase "Different input produces different hash" <| fun _ ->
                hash (Key.None) HashLength.recommended [| 1uy; 2uy; 3uy |]
                <>! hash (Key.None) HashLength.recommended [| 1uy; 2uy |]
            testCase "Different key produces different hash" <| fun _ ->
                let keyLength = KeyLength.recommended
                let key1 = Key.Generate keyLength
                let key2 = Key.Generate keyLength
                let input = [| 1uy; 2uy; 3uy |]
                hash key1 HashLength.recommended input
                <>! hash key2 HashLength.recommended input
        ]
        testList "Parts" [
            testCase "Same input produces same hash with no key" <| fun _ ->
                let hash () =
                    result {
                        let! state = State.Make(Key.None, HashLength.recommended)
                        let hashPart = hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! completeHash state
                    }
                    |> Result.failOnError "Hashing failed"
                hash () =! hash ()
            testCase "Same input produces same hash with key" <| fun _ ->
                let hash key =
                    result {
                        let! state = State.Make(key, HashLength.recommended)
                        let hashPart = hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! completeHash state
                    }
                    |> Result.failOnError "Hashing failed"
                let keyLength = KeyLength.recommended
                let key = Key.Generate keyLength
                hash key =! hash key
            testCase "Different input produces different hash" <| fun _ ->
                let hash firstPart =
                    result {
                        let! state = State.Make(Key.None, HashLength.recommended)
                        let hashPart = hashPart state
                        do! hashPart firstPart
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! completeHash state
                    }
                    |> Result.failOnError "Hashing failed"
                hash [|1uy; 2uy|] <>! hash [|1uy|]
            testCase "Different key produces different hash" <| fun _ ->
                let hash key =
                    result {
                        let! state = State.Make(key, HashLength.recommended)
                        let hashPart = hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! completeHash state
                    }
                    |> Result.failOnError "Hashing failed"
                let keyLength = KeyLength.recommended
                let key1 = Key.Generate keyLength
                let key2 = Key.Generate keyLength
                hash key1 <>! hash key2
            testCase "Produces same hash as all at once API" <| fun _ ->
                let hashPart1 =
                    result {
                        let! state = State.Make(Key.None, HashLength.recommended)
                        let hashPart = hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! completeHash state
                    }
                    |> Result.failOnError "Hashing failed"
                let hashPart2 =
                    result {
                        let! state = State.Make(Key.None, HashLength.recommended)
                        let hashPart = hashPart state
                        do! hashPart [|1uy; 2uy; 3uy|]
                        do! hashPart [|4uy; 5uy|]
                        return! completeHash state
                    }
                    |> Result.failOnError "Hashing failed"
                let allAtOnceHash =
                    hash (Key.None) HashLength.recommended [|1uy; 2uy; 3uy; 4uy; 5uy|]
                    |> Result.failOnError "Hashing failed"
                hashPart1 =! hashPart2
                hashPart1 =! allAtOnceHash
        ]
    ]
