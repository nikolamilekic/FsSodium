[<AutoOpen>]
module FsSodium.Extensions

open System
open Milekic.YoLo.Validation

[<Obsolete>]
let validateRange minimum maximum constructor x =
    if x < minimum then Error ValueIsTooSmall
    elif x > maximum then Error ValueIsTooBig
    else Ok <| constructor x

[<Obsolete>]
type ArrayLengthValidationError = ArrayIsOfWrongLength

[<Obsolete>]
let validateArrayLength expectedLength constructor x =
    if Array.length x = expectedLength
    then Ok <| constructor x
    else Error ArrayIsOfWrongLength
