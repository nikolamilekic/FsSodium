[<AutoOpen>]
module YoLo

open System.Threading

let rec atomicUpdateQuery state update =
    let oldState = !state
    let result, newState = update oldState
    let ok = Interlocked.CompareExchange<_>(state, newState, oldState)
             |> LanguagePrimitives.PhysicalEquality oldState
    if ok then result, newState else atomicUpdateQuery state update
let atomicUpdateQueryResult s u = (s, u) ||> atomicUpdateQuery |> fst
let atomicUpdate state update =
    atomicUpdateQuery state (fun s -> (), update s) |> snd
let curry f a b = f(a, b)
let uncurry f (a, b) = f a b
let flip f a b = f b a

[<AbstractClass; Sealed>]
type Tuple private () =
    static member Untuple((a, b), c) = (a, b, c)
    static member Untuple(((a, b), c), d) = (a, b, c, d)
    static member Untuple((((a, b), c), d), e) = (a, b, c, d, e)

module Async =
    let liftValue x = async { return x }
    let map f x = async { let! result = x in return f result }
    let bind f e = async { let! x = e in return! f x }

module Option =
    open Option

    let either some none = function | Some x -> some x | None -> none()

    module Operators =
        let inline (>>=) e f = bind f e

    type Builder() =
        member __.Bind(e, f) = bind f e
        member __.Return x = Some x
        member __.ReturnFrom x = x

    type First() =
        member __.Yield x = Some x
        member __.YieldFrom x = x
        member __.Combine(x, fY) = orElseWith fY x

let option = Option.Builder()
let first = Option.First()

module Result =
    open Result

    let either ok error = function | Ok x -> ok x | Error x -> error x
    let liftChoice = function | Choice1Of2 x -> Ok x
                              | Choice2Of2 error -> Error error
    let toChoice e = e |> either Choice1Of2 Choice2Of2
    let fromOption error = Option.either Ok (fun _ -> Error error)
    let isOk e = either (fun _ -> true) (fun _ -> false) e
    let isError e = isOk e |> not
    let tryWith handler f = try f() |> Ok with exn -> handler exn |> Error
    let catch f = tryWith id f
    let defaultWith f = either id f
    let defaultValue x = defaultWith (fun _ -> x)
    let failOnError message = defaultWith <| fun _ -> failwith message

    module Operators =
        let inline (>>=) e f = bind f e
        let inline (>=>) f1 f2 e = f1 e >>= f2
        let inline (>>-) e f = map f e

    open Operators

    let traverse f source =
        let folder element state = state >>= (fun tail ->
                                   f element >>= (fun head ->
                                   Ok (head::tail)))
        List.foldBack folder source (Ok [])

    type Builder() =
        member __.Bind(e, f) = bind f e
        member __.Return x = Ok x
        member __.ReturnFrom x = x

let result = Result.Builder()

type Update<'s, 'u, 'a> = Update of ('s -> 'u * 'a)
module Update =
    let inline unit< ^u when ^u : (static member Unit : ^u)> : ^u =
        (^u : (static member Unit : ^u) ())
    let inline combine< ^u when ^u : (static member Combine : ^u * ^u -> ^u)>
        (a, b) : ^u = (^u : (static member Combine : ^u * ^u -> ^u) (a, b))
    let inline apply< ^s, ^u when ^u : (static member Apply : ^s * ^u -> ^s)>
        (state, update) : ^s =
        (^u : (static member Apply : ^s * ^u -> ^s) (state, update))
    let run state (Update f) = f state
    let inline liftValue x = Update (fun _ -> (unit, x))
    let inline bind f e = fun s0 -> let (u1, r1) = run s0 e
                                    let s1 = apply (s0, u1)
                                    let (u2, r2) = run s1 (f r1)
                                    combine (u1, u2), r2
                          |> Update
    let inline map f = (f >> liftValue) |> bind

    type Builder() =
        member inline __.Return x = liftValue x
        member __.ReturnFrom x = x
        member inline __.Bind(e, f) = bind f e
        member inline __.Zero() = liftValue ()
        member inline __.Delay(f) = bind f (liftValue ())
        member inline __.Using(disposable, body) =
            fun state -> use disposable = disposable
                         let (Update inner) = body disposable
                         inner state
            |> Update

let update = Update.Builder()

type SimpleUpdate<'s> =
    DoNothing | Simple of ('s -> 's)
    static member Apply (s, u) = match u with | DoNothing -> s | Simple f -> f s
    static member Unit : SimpleUpdate<'s> = DoNothing
    static member Combine(a, b) = match (a, b) with
                                  | DoNothing, x
                                  | x, DoNothing -> x
                                  | Simple a, Simple b -> Simple (a >> b)

module SimpleUpdate =
    let applyUpdate updateF : Update<'s, SimpleUpdate<'s>, unit> =
        (fun _ -> Simple updateF, ()) |> Update
    let read f : Update<'s, SimpleUpdate<_>, _> =
        (fun state -> DoNothing, f state) |> Update
    let get<'s> : Update<'s, SimpleUpdate<'s>, _>= read id


type Log<'a> = | Log of 'a list
               static member Unit : Log<'a> = Log []
               static member Apply((), _) = ()
               static member Combine(Log a, Log b) = List.append a b |> Log

module Log =
    let private wrap x = (fun () -> x, ()) |> Update
    let logMany x = Log x |> wrap
    let log x = logMany [x]

type Eventually<'a> =
    | Done of 'a
    | NotDone of (unit -> Eventually<'a>)
module Eventually =
    let rec bind f = function
        | Done x -> NotDone (fun () -> f x)
        | NotDone inner -> NotDone (fun () -> bind f (inner()))
    let map f = f >> Done |> bind
    let delay f = f >> Done |> NotDone
    let rec run = function | Done x -> x | NotDone next -> next() |> run
    let (>>=) e f = bind f e
