module FsSodium.Tests.HashingTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium.Hashing

initializeSodium()

[<Tests>]
let hashingTests =
    testList "Hashing" [
        testList "All at once" [
            testCase "Same input produces same hash with no key" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                Hashing.hash (HashingKey.None) HashLength.Recommended input
                =! Hashing.hash (HashingKey.None) HashLength.Recommended input
            testCase "Same input produces same hash with key" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                let keyLength = HashingKeyLength.Recommended
                let key = HashingKey.Generate keyLength
                Hashing.hash key HashLength.Recommended input
                =! Hashing.hash key HashLength.Recommended input
            testCase "Different input produces different hash" <| fun _ ->
                Hashing.hash
                    (HashingKey.None) HashLength.Recommended [| 1uy; 2uy; 3uy |]
                <>! Hashing.hash
                    (HashingKey.None) HashLength.Recommended [| 1uy; 2uy |]
            testCase "Different key produces different hash" <| fun _ ->
                let keyLength = HashingKeyLength.Recommended
                let key1 = HashingKey.Generate keyLength
                let key2 = HashingKey.Generate keyLength
                let input = [| 1uy; 2uy; 3uy |]
                Hashing.hash key1 HashLength.Recommended input
                <>! Hashing.hash key2 HashLength.Recommended input
        ]
        testList "Parts" [
            testCase "Same input produces same hash with no key" <| fun _ ->
                let hash () =
                    monad {
                        let! state =
                            HashingState.Create(
                                HashingKey.None, HashLength.Recommended)
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
                        let! state =
                            HashingState.Create(
                                key, HashLength.Recommended)
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let keyLength = HashingKeyLength.Recommended
                let key = HashingKey.Generate keyLength
                hash key =! hash key
            testCase "Different input produces different hash" <| fun _ ->
                let hash firstPart =
                    monad {
                        let! state =
                            HashingState.Create(
                                HashingKey.None, HashLength.Recommended)
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
                        let! state =
                            HashingState.Create(key, HashLength.Recommended)
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let keyLength = HashingKeyLength.Recommended
                let key1 = HashingKey.Generate keyLength
                let key2 = HashingKey.Generate keyLength
                hash key1 <>! hash key2
            testCase "Produces same hash as all at once API" <| fun _ ->
                let hashPart1 =
                    monad {
                        let! state =
                            HashingState.Create(
                                HashingKey.None, HashLength.Recommended)
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let hashPart2 =
                    monad {
                        let! state =
                            HashingState.Create(
                                HashingKey.None, HashLength.Recommended)
                        let hashPart = Hashing.hashPart state
                        do! hashPart [|1uy; 2uy; 3uy|]
                        do! hashPart [|4uy; 5uy|]
                        return! Hashing.completeHash state
                    }
                    |> Result.get
                let allAtOnceHash =
                    Hashing.hash
                        HashingKey.None
                        HashLength.Recommended
                        [|1uy; 2uy; 3uy; 4uy; 5uy|]
                    |> Result.get
                hashPart1 =! hashPart2
                hashPart1 =! allAtOnceHash
        ]
    ]
