namespace FsSodium

open System
open System.Globalization
open System.Runtime.InteropServices
open FSharpPlus.Math.Generic

type SodiumError = SodiumError of int
type MacLength = MacLength of int with member this.Get = let (MacLength x) = this in x
type CipherText = CipherText of byte[]
type PlainText = PlainText of byte[]

[<RequireQualifiedAccess>]
module Sodium =
    let initialize =
        let initialize =
            lazy
            match Interop.sodium_init() with
            | 0 | 1 -> ()
            | _ -> failwith "Sodium could not be initialized"
        initialize.Force

    let getSodiumVersion =
        let version =
            lazy
            initialize ()
            let intPtr = Interop.sodium_version_string()
            Marshal.PtrToStringAnsi(intPtr)
        version.Force


    let getCipherTextLength (MacLength macLength) plainTextLength =
        if plainTextLength <= 0 then 0 else plainTextLength + macLength
    let getPlainTextLength (MacLength macLength) cipherTextLength =
        if cipherTextLength <= macLength
        then 0
        else cipherTextLength - macLength

module Parsing =
    let parseByteArrayFromHexString x =
        Seq.chunkBySize 2 x
        |> Seq.map (String >> fun s -> Byte.Parse(s, NumberStyles.AllowHexSpecifier))
        |> Seq.toArray
    let byteArrayToHexString (x : byte seq) = x |> Seq.fold (fun s x -> s + $"%02x{x}") ""
