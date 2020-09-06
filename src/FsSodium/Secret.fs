namespace FsSodium

open System

type Secret(secret) =
    let secretLength = Array.length secret |> uint32
    do
        Sodium.initialize ()
        Interop.sodium_mlock(secret, secretLength) |> ignore
    abstract member Dispose : unit -> unit
    default __.Dispose() =
        Interop.sodium_munlock(secret, secretLength) |> ignore
    member __.Get = secret
    interface IDisposable with
        member this.Dispose() = this.Dispose(); GC.SuppressFinalize this
    override this.Finalize() = this.Dispose()
