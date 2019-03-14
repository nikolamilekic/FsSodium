namespace FsSodium

open System
open System.Runtime.CompilerServices

module Sodium =

    [<assembly: InternalsVisibleTo("FsSodium.Tests")>]
    do ()

    type InitializationError = SodiumError of int
    let initialize() =
        match Interop.sodium_init() with
        | 0 | 1 -> Ok ()
        | result -> Error <| SodiumError result

[<AutoOpen>]
module Helpers =
    type ValidateRangeError = ValueIsTooSmall | ValueIsTooBig

    let inline
        validateRange< ^a, 'b, 'c when ^a : (static member Maximum : 'b) and
                                       ^a : (static member Minimum : 'b) and
                                       'b : comparison>
            (ctor : 'b -> ^a) x =
        let minimum = (^a : (static member Minimum : 'b) ())
        let maximum = (^a : (static member Maximum : 'b) ())
        if x < minimum then Error ValueIsTooSmall
        elif x > maximum then Error ValueIsTooBig
        else Ok <| ctor x

    let capToInt x = [ x; Int32.MaxValue |> uint64 ] |> List.min |> int

    let (>>-!) x f = Result.mapError f x
    let (>>-!.) x error = Result.mapError (fun _ -> error) x
    let (>>-.) x value = Result.map (fun _ -> value) x
