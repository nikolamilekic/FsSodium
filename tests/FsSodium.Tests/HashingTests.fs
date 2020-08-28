module FsSodium.Tests.HashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium

initializeSodium()

let hashRecommended key = Hashing.hash key Hashing.HashLength.Recommended
let zeroKey = Hashing.Key.None
let createStateRecommended key =
    Hashing.State.Create(key, Hashing.HashLength.Recommended)
let generateRecommendedKey () =
    Hashing.Key.Generate Hashing.KeyLength.Recommended

[<Tests>]
let hashingTests =
    testList "Generic hashing" [
        testList "All at once" [
            testCase "Same input produces same hash with no key" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                hashRecommended zeroKey input =! hashRecommended zeroKey input
            testCase "Same input produces same hash with key" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                let key = generateRecommendedKey ()
                hashRecommended key input =! hashRecommended key input
            testCase "Different input produces different hash" <| fun _ ->
                hashRecommended zeroKey [| 1uy; 2uy; 3uy |]
                <>! hashRecommended zeroKey [| 1uy; 2uy |]
            testCase "Different key produces different hash" <| fun _ ->
                let key1 = generateRecommendedKey ()
                let key2 = generateRecommendedKey ()
                let input = [| 1uy; 2uy; 3uy |]
                hashRecommended key1 input <>! hashRecommended key2 input
        ]
        testList "Parts" [
            testCase "Same input produces same hash with no key" <| fun _ ->
                let hash () =
                    monad {
                        let! state = createStateRecommended zeroKey
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                hash () =! hash ()
            testCase "Same input produces same hash with key" <| fun _ ->
                let hash key =
                    monad {
                        let! state = createStateRecommended key
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let key = generateRecommendedKey ()
                hash key =! hash key
            testCase "Different input produces different hash" <| fun _ ->
                let hash firstPart =
                    monad {
                        let! state = createStateRecommended zeroKey
                        let hashPart = Hashing.hashPart state
                        do! hashPart firstPart
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                hash [|1uy; 2uy|] <>! hash [|1uy|]
            testCase "Different key produces different hash" <| fun _ ->
                let hash key =
                    monad {
                        let! state = createStateRecommended key
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let key1 = generateRecommendedKey ()
                let key2 = generateRecommendedKey ()
                hash key1 <>! hash key2
            testCase "Produces same hash as all at once API" <| fun _ ->
                let hashPart1 =
                    monad {
                        let! state = createStateRecommended zeroKey
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let hashPart2 =
                    monad {
                        let! state = createStateRecommended zeroKey
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy; 3uy|]
                        do! hashPart [|4uy; 5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let allAtOnceHash =
                    hashRecommended zeroKey [|1uy; 2uy; 3uy; 4uy; 5uy|]
                    |> Result.get
                hashPart1 =! hashPart2
                hashPart1 =! allAtOnceHash
        ]
    ]
