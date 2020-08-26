namespace FsSodium.PasswordHashing

open Milekic.YoLo
open FSharpPlus

open FsSodium

module internal AlgorithmInfo =
    let saltLength = Interop.crypto_pwhash_saltbytes() |> int
    let numberOfOperationsMaximumCount = Interop.crypto_pwhash_opslimit_max()
    let numberOfOperationsMinimumCount = Interop.crypto_pwhash_opslimit_min()
    let algorithmDefault = Interop.crypto_pwhash_alg_default()
    let memoryLimitMaximum = Interop.crypto_pwhash_memlimit_max()
    let memoryLimitMinimum = Interop.crypto_pwhash_memlimit_min()
    let keyMaximumLength = Interop.crypto_pwhash_bytes_max()
    let keyMinimumLength = Interop.crypto_pwhash_bytes_min()
    let passwordMinimumLength = Interop.crypto_pwhash_passwd_min()
    let passwordMaximumLength = Interop.crypto_pwhash_passwd_max()

open AlgorithmInfo

type Salt = private | Salt of byte[] with
    static member Generate() = Random.bytes saltLength |> Salt
    static member Import x =
        if Array.length x <> saltLength then Error () else Ok <| Salt x
    member this.Get = let (Salt x) = this in x
type NumberOfOperations = private | NumberOfOperations of uint64 with
    static member Minimum = NumberOfOperations numberOfOperationsMinimumCount
    static member Maximum = NumberOfOperations numberOfOperationsMaximumCount
    static member Custom x =
        let casted = uint64 x
        if casted < numberOfOperationsMinimumCount ||
            casted > numberOfOperationsMaximumCount
        then Error ()
        else Ok <| NumberOfOperations x
    member this.Get = let (NumberOfOperations x) = this in int x
type Algorithm = Default with
    static member Parse = function
        | x when x = algorithmDefault -> Ok Default
        | _ -> Error ()
    member this.ToInt = match this with Default -> algorithmDefault
type MemoryLimit = private | MemoryLimit of uint32 with
    static member Custom x =
        if x < memoryLimitMinimum || x > memoryLimitMaximum
        then Error ()
        else Ok <| MemoryLimit x
    static member Minimum = MemoryLimit memoryLimitMinimum
    static member Maximum = MemoryLimit memoryLimitMaximum
    member this.Get = let (MemoryLimit x) = this in uint32 x

type HashPasswordParameters = {
    NumberOfOperations : NumberOfOperations
    MemoryLimit : MemoryLimit
    Algorithm : Algorithm
    Salt : Salt
}
module HashPasswordParameters =
    let inline _numberOfOperations f s =
        s.NumberOfOperations |> f <&> fun v -> { s with NumberOfOperations = v }
    let inline _memoryLimit f s =
        s.MemoryLimit |> f <&> fun v -> { s with MemoryLimit = v }
    let inline _algorithm f s =
        s.Algorithm |> f <&> fun v -> { s with Algorithm = v }
    let inline _salt f s = s.Salt |> f <&> fun v -> { s with Salt = v }

type KeyLength = private | KeyLength of uint32 with
    static member Validate x =
        x
        |> Result.protect uint32
        |> first ignore
        >>= (fun x ->
            if x < keyMinimumLength || x > keyMaximumLength
            then Error ()
            else Ok <| KeyLength x)
    member this.Get = let (KeyLength x) = this in int x
type Password private (secret) =
    inherit Secret(secret)
    static member Import secret =
        let length = Array.length secret |> uint32
        let password = new Password(secret)

        if length < passwordMinimumLength || length > passwordMaximumLength
        then password.Dispose(); Error ()
        else Ok password
[<RequireQualifiedAccess>]
module PasswordHashing =
    let hashPassword
        (KeyLength keyLength)
        {
            Salt = (Salt salt)
            Algorithm = algorithm
            NumberOfOperations = (NumberOfOperations operations)
            MemoryLimit = (MemoryLimit memory)
        }
        (password : Password) =
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
