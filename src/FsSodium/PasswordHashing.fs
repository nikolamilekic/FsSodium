[<RequireQualifiedAccess>]
module FsSodium.PasswordHashing

open Milekic.YoLo
open FSharpPlus

let private saltLength = lazy (Interop.crypto_pwhash_saltbytes() |> int)
let private numberOfOperationsMaximumCount = lazy Interop.crypto_pwhash_opslimit_max()
let private numberOfOperationsMinimumCount = lazy Interop.crypto_pwhash_opslimit_min()
let private numberOfOperationsInteractiveCount = lazy Interop.crypto_pwhash_opslimit_interactive()
let private numberOfOperationsModerateCount = lazy Interop.crypto_pwhash_opslimit_moderate()
let private numberOfOperationsSensitiveCount = lazy Interop.crypto_pwhash_opslimit_sensitive()
let private algorithmDefault = lazy Interop.crypto_pwhash_alg_default()
let private memoryLimitMaximum = lazy Interop.crypto_pwhash_memlimit_max()
let private memoryLimitMinimum = lazy Interop.crypto_pwhash_memlimit_min()
let private memoryLimitInteractive = lazy Interop.crypto_pwhash_memlimit_interactive()
let private memoryLimitModerate = lazy Interop.crypto_pwhash_memlimit_moderate()
let private memoryLimitSensitive = lazy Interop.crypto_pwhash_memlimit_sensitive()
let private keyMaximumLength = lazy Interop.crypto_pwhash_bytes_max()
let private keyMinimumLength = lazy Interop.crypto_pwhash_bytes_min()
let private passwordMinimumLength = lazy Interop.crypto_pwhash_passwd_min()
let private passwordMaximumLength = lazy Interop.crypto_pwhash_passwd_max()

type Salt = private | Salt of byte[] with
    static member Generate() =
        Sodium.initialize ()
        Random.bytes saltLength.Value |> Salt
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> saltLength.Value then Error () else Ok <| Salt x
    member this.Get = let (Salt x) = this in x
type NumberOfOperations = private | NumberOfOperations of uint64 with
    static member Minimum =
        Sodium.initialize ()
        NumberOfOperations numberOfOperationsMinimumCount.Value
    static member Maximum =
        Sodium.initialize ()
        NumberOfOperations numberOfOperationsMaximumCount.Value
    static member Interactive =
        Sodium.initialize ()
        NumberOfOperations numberOfOperationsInteractiveCount.Value
    static member Moderate =
        Sodium.initialize ()
        NumberOfOperations numberOfOperationsModerateCount.Value
    static member Sensitive =
        Sodium.initialize ()
        NumberOfOperations numberOfOperationsSensitiveCount.Value
    static member Custom x =
        Sodium.initialize ()
        let casted = uint64 x
        if casted < numberOfOperationsMinimumCount.Value ||
            casted > numberOfOperationsMaximumCount.Value
        then Error ()
        else Ok <| NumberOfOperations x
    member this.Get = let (NumberOfOperations x) = this in int x
type Algorithm = Default with
    static member Parse x =
        Sodium.initialize ()
        match x with
        | x when x = algorithmDefault.Value -> Ok Default
        | _ -> Error ()
    member this.ToInt =
        Sodium.initialize ()
        match this with Default -> algorithmDefault.Value
type MemoryLimit = private | MemoryLimit of uint32 with
    static member Custom x =
        Sodium.initialize ()
        if x < memoryLimitMinimum.Value || x > memoryLimitMaximum.Value
        then Error ()
        else Ok <| MemoryLimit x
    static member Minimum =
        Sodium.initialize ()
        MemoryLimit memoryLimitMinimum.Value
    static member Maximum =
        Sodium.initialize ()
        MemoryLimit memoryLimitMaximum.Value
    static member Interactive =
        Sodium.initialize ()
        MemoryLimit memoryLimitInteractive.Value
    static member Moderate =
        Sodium.initialize ()
        MemoryLimit memoryLimitModerate.Value
    static member Sensitive =
        Sodium.initialize ()
        MemoryLimit memoryLimitSensitive.Value
    member this.Get = let (MemoryLimit x) = this in uint32 x
type HashPasswordParameters = {
    NumberOfOperations : NumberOfOperations
    MemoryLimit : MemoryLimit
    Algorithm : Algorithm
    Salt : Salt
}
type KeyLength = private | KeyLength of uint32 with
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
type Password private (secret) =
    inherit Secret(secret)
    static member Import password =
        Sodium.initialize ()
        let length = Array.length password |> uint32
        if length < passwordMinimumLength.Value ||
            length > passwordMaximumLength.Value
        then Error ()
        else Ok <| new Password(password)

let hashPassword
    (KeyLength keyLength)
    {
        Salt = (Salt salt)
        Algorithm = algorithm
        NumberOfOperations = (NumberOfOperations operations)
        MemoryLimit = (MemoryLimit memory)
    }
    (password : Password) =

    Sodium.initialize ()

    let secret = Array.zeroCreate (int keyLength)
    let result =
        Interop.crypto_pwhash(
            secret,
            (uint64 keyLength),
            password.Get,
            (Array.length password.Get |> uint64),
            salt,
            operations,
            memory,
            algorithm.ToInt)
    if result = 0
    then Ok secret
    else Error <| SodiumError result
