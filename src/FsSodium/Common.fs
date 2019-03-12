namespace FsSodium

open System
open System.ComponentModel
open Milekic.YoLo.Result.Operators

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
            then Error <| sprintf "%s cannot be less than %A." name minimum
            else Ok x
        let maximumCheck x =
            if x > maximum
            then Error <| sprintf "%s cannot be bigger than %A." name maximum
            else Ok x
        minimumCheck x >>= maximumCheck >>- ctor

    let capToInt x = [ x; Int32.MaxValue |> uint64 ] |> List.min |> int
