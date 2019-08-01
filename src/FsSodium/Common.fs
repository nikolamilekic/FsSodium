namespace FsSodium

open System
open System.Runtime.CompilerServices
open System.Runtime.InteropServices

type SodiumError = SodiumError of int
module Sodium =

    [<assembly: InternalsVisibleTo("FsSodium.Tests")>]
    do ()

    let initialize() =
        match Interop.sodium_init() with
        | 0 | 1 -> Ok ()
        | result -> Error <| SodiumError result

    let getLibsodiumVersion() =
        let intPtr = Interop.sodium_version_string()
        Marshal.PtrToStringAnsi(intPtr)

[<AutoOpen>]
module Helpers =
    let capToInt x = [ x; Int32.MaxValue |> uint64 ] |> List.min |> int
