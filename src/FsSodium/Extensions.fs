[<AutoOpen>]
module FsSodium.Extensions

open Milekic.YoLo.Validation

let validateRange minimum maximum constructor x =
    if x < minimum then Error ValueIsTooSmall
    elif x > maximum then Error ValueIsTooBig
    else Ok <| constructor x

type ArrayLengthValidationError = ArrayIsOfWrongLength
let validateArrayLength expectedLength constructor x =
    if Array.length x = expectedLength
    then Ok <| constructor x
    else Error ArrayIsOfWrongLength
