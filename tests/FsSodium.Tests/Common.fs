[<AutoOpen>]
module FsSodium.Tests.Common

open Milekic.YoLo
open FsSodium

let initializeSodium =
    Sodium.initialize >>  Result.failOnError "Sodium initialization failed"
