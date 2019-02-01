namespace FsSodium

open System
open System.Runtime.Serialization
open Milekic.YoLo

type Secret(secret) =
    static let secretName = nameOf <@ instanceOf<Secret>.Secret @>
    let secretLength = Array.length secret
    do Interop.sodium_mlock(secret, secretLength) |> ignore
    let dispose () = Interop.sodium_munlock(secret, secretLength) |> ignore

    member __.Secret = secret
    new(info : SerializationInfo, _ : StreamingContext) =
        let secret = info.GetValue (secretName, typeof<byte[]>) :?> byte[]
        new Secret(secret)
    interface IDisposable with
        member this.Dispose() = dispose(); GC.SuppressFinalize this
    override __.Finalize() = dispose()
    interface ISerializable with
        member __.GetObjectData(info, _) = info.AddValue (secretName, secret)
