[<RequireQualifiedAccess>]
module FsSodium.KeyDerivation

open System.Text
open Milekic.YoLo
open FSharpPlus

let private keyMaximumLength = lazy Interop.crypto_kdf_bytes_max()
let private keyMinimumLength = lazy Interop.crypto_kdf_bytes_min()
let private masterKeyLength = lazy (Interop.crypto_kdf_keybytes() |> int)
let private contextLength = lazy (Interop.crypto_kdf_contextbytes() |> int)

type MasterKey private (key) =
    inherit Secret(key)
    static member Generate() =
        Sodium.initialize ()
        let key = new MasterKey(Array.zeroCreate masterKeyLength.Value)
        Interop.crypto_kdf_keygen(key.Get)
        key
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> masterKeyLength.Value
        then Error () else Ok <| new MasterKey(x)
type KeyLength = private KeyLength of uint32 with
    static member Validate x =
        Sodium.initialize ()
        x
        |> Result.protect uint32
        |> Result.mapError ignore
        >>= (fun x ->
            if x < keyMinimumLength.Value || x > keyMaximumLength.Value
            then Error ()
            else Ok <| KeyLength x)
    member this.Get = let (KeyLength x) = this in int x
type Context = private Context of byte[] with
    static member Validate (x : string) =
        Sodium.initialize ()
        let bytes = Encoding.ASCII.GetBytes x
        if Array.length bytes = contextLength.Value
        then Ok <| Context bytes else Error ()
    member this.Get = let (Context x) = this in x
let deriveKey (masterKey : MasterKey) (Context context) keyId (KeyLength length) =
    Sodium.initialize ()
    let key = Array.zeroCreate (int length)
    let result =
        Interop.crypto_kdf_derive_from_key(
            key,
            length,
            keyId,
            context,
            masterKey.Get)
    if result = 0
    then Ok key
    else Error <| SodiumError result
