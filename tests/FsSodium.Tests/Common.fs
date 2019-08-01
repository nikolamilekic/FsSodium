[<AutoOpen>]
module FsSodium.Tests.Common

open Milekic.YoLo
open FsSodium
open Expecto

let initializeSodium =
    Sodium.initialize >>  Result.failOnError "Sodium initialization failed"

[<Tests>]
let versionDoesNotThrow =
    testCase "Version does not throw" <| fun _ ->
        Expect.isNotNull "Version string is null" (FsSodium.Sodium.getLibsodiumVersion())
