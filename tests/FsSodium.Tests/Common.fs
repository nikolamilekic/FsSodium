[<AutoOpen>]
module FsSodium.Tests.Common

open FsSodium
open Expecto

[<Tests>]
let versionDoesNotThrow =
    testCase "Version does not throw" <| fun _ ->
        Expect.isNotNull "Version string is null" (Sodium.getSodiumVersion())
