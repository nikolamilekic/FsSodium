namespace FsSodium

open System
open System.Runtime.Serialization
open Milekic.YoLo

type Secret(secret) =
    static let secretName = nameOf <@ instanceOf<Secret>.Secret @>
    let secretLength = Array.length secret |> uint32
    do Interop.sodium_mlock(secret, secretLength) |> ignore
    new(info : SerializationInfo, _ : StreamingContext) =
        let secret = info.GetValue (secretName, typeof<byte[]>) :?> byte[]
        new Secret(secret)
    abstract member Dispose : unit -> unit
    default __.Dispose() =
        Interop.sodium_munlock(secret, secretLength) |> ignore
    member __.Secret = secret
    interface IDisposable with
        member this.Dispose() = this.Dispose(); GC.SuppressFinalize this
    override this.Finalize() = this.Dispose()
    interface ISerializable with
        member __.GetObjectData(info, _) = info.AddValue (secretName, secret)
