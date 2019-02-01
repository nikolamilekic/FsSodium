namespace FsSodium

open System
open System.Runtime.Serialization
open Milekic.YoLo

type Secret(secret) =
    static let secretName = nameOf <@ instanceOf<Secret>.Secret @>
    let secretLength = Array.length secret
    do
        let result = Interop.sodium_mlock(secret, secretLength)
        if result <> 0 then
            Interop.sodium_memzero(secret, secretLength)
            failwith "Failed to lock memory."
    member __.Secret = secret
    new(info : SerializationInfo, _ : StreamingContext) =
        let secret = info.GetValue (secretName, typeof<byte[]>) :?> byte[]
        new Secret(secret)
    interface IDisposable with
        member __.Dispose() =
            let result = Interop.sodium_munlock(secret, secretLength)
            if result <> 0 then
                Interop.sodium_memzero(secret, secretLength)
                failwith "Failed to unlock memory."
    override this.Finalize() = (this :> IDisposable).Dispose()
    interface ISerializable with
        member __.GetObjectData(info, _) = info.AddValue (secretName, secret)
