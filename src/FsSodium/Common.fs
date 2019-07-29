namespace FsSodium

open System
open System.Runtime.CompilerServices

type SodiumError = SodiumError of int
module Sodium =

    [<assembly: InternalsVisibleTo("FsSodium.Tests")>]
    do ()

    let initialize() =
        match Interop.sodium_init() with
        | 0 | 1 -> Ok ()
        | result -> Error <| SodiumError result

[<AutoOpen>]
module Helpers =
    let capToInt x = [ x; Int32.MaxValue |> uint64 ] |> List.min |> int
