module FsSodium.PasswordHashing

open System
open System.ComponentModel
open Milekic.YoLo

module internal Salt = let length = Interop.crypto_pwhash_saltbytes()
type Salt = private Salt of byte[]
    with static member Generate() = Random.bytes Salt.length |> Salt

module internal NumberOfOperations =
    let maximum = Interop.crypto_pwhash_opslimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_opslimit_min() |> capToInt
[<Description("Number of operations")>]
type NumberOfOperations = private NumberOfOperations of uint64
    with
        static member Maximum = NumberOfOperations.maximum
        static member Minimum = NumberOfOperations.minimum
        static member Create = validateRange (uint64 >> NumberOfOperations)

type Algorithm = private Algorithm of int
    with static member Default = Interop.crypto_pwhash_alg_default() |> Algorithm

module internal MemoryLimit =
    let maximum = Interop.crypto_pwhash_memlimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_memlimit_min() |> capToInt
[<Description("Memory limit")>]
type MemoryLimit = private MemoryLimit of uint64
    with
        static member Maximum = MemoryLimit.maximum
        static member Minimum = MemoryLimit.minimum
        static member Create = validateRange (uint64 >> MemoryLimit)

type HashPasswordParameters = {
    NumberOfOperations : NumberOfOperations
    MemoryLimit : MemoryLimit
    Algorithm : Algorithm
    Salt : Salt
}

module internal KeyLength =
    let maximum = Interop.crypto_pwhash_bytes_max() |> capToInt
    let minimum = Interop.crypto_pwhash_bytes_min() |> capToInt
type KeyLength = private KeyLength of int
    with
        static member Maximum = KeyLength.maximum
        static member Minimum = KeyLength.minimum
        static member Create = validateRange KeyLength

module internal Password =
    let minimumLength = Interop.crypto_pwhash_passwd_min() |> capToInt
    let maximumLength = Interop.crypto_pwhash_passwd_max() |> capToInt
type Password private (secret) =
    inherit Secret(secret)
    static member CreateDisposable secret =
        let password = new Password(secret)
        result {
            let length = Array.length secret
            if length < Password.minimumLength then
                return! Error "Password is too short"
            elif length > Password.maximumLength then
                return! Error "Password is too long"
            else return password
        }
        |> Result.either Ok (fun x -> password.Dispose(); Error x)

let hashPassword
    (KeyLength keyLength)
    {
        Salt = (Salt salt)
        Algorithm = (Algorithm algorithm)
        NumberOfOperations = (NumberOfOperations operations)
        MemoryLimit = (MemoryLimit memory)
    }
    (password : Password) =
    let secret = Array.zeroCreate keyLength
    let result =
        Interop.crypto_pwhash(
            secret,
            (uint64 keyLength),
            password.Secret,
            (Array.length password.Secret |> uint64),
            salt,
            operations,
            memory,
            algorithm)
    if result = 0
    then Ok secret
    else
        sprintf "Libsodium could not hash password but instead returned with error code %d. This probably happened because not enough memory could be allocated." result
        |> Error
