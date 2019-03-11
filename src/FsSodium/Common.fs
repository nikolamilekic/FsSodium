namespace FsSodium

open System
open System.ComponentModel
open Chessie.ErrorHandling

type PlainText = PlainText of byte[]

module Sodium =
    let initialize() =
        if Interop.sodium_init() = -1
        then failwith "Could not initialize Sodium"

[<AutoOpen>]
module Helpers =
    let inline
        validateRange< ^a, 'b, 'c when ^a : (static member Maximum : 'b) and
                                       ^a : (static member Minimum : 'b) and
                                       'b : comparison> (ctor : 'b -> ^a) x =
        let minimum = (^a : (static member Minimum : 'b) ())
        let maximum = (^a : (static member Maximum : 'b) ())
        let name =
            let aType = typeof< ^a>
            aType.GetCustomAttributes(true)
            |> Seq.tryFind (fun x -> x :? DescriptionAttribute)
            |> Option.map (fun x -> (x :?> DescriptionAttribute).Description)
            |> Option.defaultValue (aType.Name)
        let minimumCheck x =
            if x < minimum
            then fail <| sprintf "%s cannot be less than %A." name minimum
            else ok x
        let maximumCheck x =
            if x > maximum
            then fail <| sprintf "%s cannot be bigger than %A." name maximum
            else ok x
        minimumCheck x >>= maximumCheck |> Trial.lift ctor

    let capToInt x = [ x; Int32.MaxValue |> uint64 ] |> List.min |> int
