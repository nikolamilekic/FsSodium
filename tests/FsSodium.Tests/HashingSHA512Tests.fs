module FsSodium.Tests.HashingSHA512Tests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium.Hashing.SHA512

initializeSodium()

[<Tests>]
let hashingTests =
    testList "SHA512 hashing" [
        testList "All at once" [
            testCase "Same input produces same hash" <| fun _ ->
                let input = [| 1uy; 2uy; 3uy |]
                SHA512.hash input =! SHA512.hash input
            testCase "Different input produces different hash" <| fun _ ->
                SHA512.hash [| 1uy; 2uy; 3uy |] <>! SHA512.hash [| 1uy; 2uy |]
        ]
        testList "Parts" [
            testCase "Same input produces same hash" <| fun _ ->
                let hash () =
                    monad {
                        let! state = SHA512State.Create()
                        let hashPart = SHA512.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! SHA512.completeHash state
                    }
                    |> Result.get
                hash () =! hash ()
            testCase "Different input produces different hash" <| fun _ ->
                let hash firstPart =
                    monad {
                        let! state = SHA512State.Create()
                        let hashPart = SHA512.hashPart state
                        do! hashPart firstPart
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! SHA512.completeHash state
                    }
                    |> Result.get
                hash [|1uy; 2uy|] <>! hash [|1uy|]
            testCase "Produces same hash as all at once API" <| fun _ ->
                let hashPart1 =
                    monad {
                        let! state = SHA512State.Create()
                        let hashPart = SHA512.hashPart state
                        do! hashPart [|1uy; 2uy|]
                        do! hashPart [|3uy; 4uy|]
                        do! hashPart [|5uy|]
                        return! SHA512.completeHash state
                    }
                    |> Result.get
                let hashPart2 =
                    monad {
                        let! state = SHA512State.Create()
                        let hashPart = SHA512.hashPart state
                        do! hashPart [|1uy; 2uy; 3uy|]
                        do! hashPart [|4uy; 5uy|]
                        return! SHA512.completeHash state
                    }
                    |> Result.get
                let allAtOnceHash =
                    SHA512.hash [|1uy; 2uy; 3uy; 4uy; 5uy|]
                    |> Result.get
                hashPart1 =! hashPart2
                hashPart1 =! allAtOnceHash
        ]
    ]
