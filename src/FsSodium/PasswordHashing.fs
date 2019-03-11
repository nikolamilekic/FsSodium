module FsSodium.PasswordHashing

open System
open System.ComponentModel
open Chessie.ErrorHandling

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

module internal MemorySize =
    let maximum = Interop.crypto_pwhash_memlimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_memlimit_min() |> capToInt
[<Description("Memory size")>]
type MemorySize = private MemorySize of uint64
    with
        static member Maximum = MemorySize.maximum
        static member Minimum = MemorySize.minimum
        static member Create = validateRange (uint64 >> MemorySize)

type HashPasswordParameters = {
    NumberOfOperations : NumberOfOperations
    MemorySize : MemorySize
    Algorithm : Algorithm
    Salt : Salt
}

module internal KeySize =
    let maximum = Interop.crypto_pwhash_bytes_max() |> capToInt
    let minimum = Interop.crypto_pwhash_bytes_min() |> capToInt
type KeySize = private KeySize of int
    with
        static member Maximum = KeySize.maximum
        static member Minimum = KeySize.minimum
        static member Create = validateRange KeySize

module internal Password =
    let minimumLength = Interop.crypto_pwhash_passwd_min() |> capToInt
    let maximumLength = Interop.crypto_pwhash_passwd_max() |> capToInt
type Password private (secret) =
    inherit Secret(secret)
    static member CreateDisposable secret =
        let password = new Password(secret)
        trial {
            let length = Array.length secret
            if length < Password.minimumLength then
                return! fail "Password is too short"
            if length > Password.maximumLength then
                return! fail "Password is too long"
            return password
        }
        |> Trial.failureTee (ignore >> password.Dispose)

let hashPassword
    (KeySize keySize)
    {
        Salt = (Salt salt)
        Algorithm = (Algorithm algorithm)
        NumberOfOperations = (NumberOfOperations operations)
        MemorySize = (MemorySize memory)
    }
    (password : Password) =
    let secret = new Secret(Array.zeroCreate keySize)
    let result =
        Interop.crypto_pwhash(
            secret.Secret,
            (uint64 keySize),
            password.Secret,
            (Array.length password.Secret |> uint64),
            salt,
            operations,
            memory,
            algorithm)
    if result = 0
    then ok secret
    else
        secret.Dispose()
        sprintf "Libsodium could not hash password but instead returned with error code %d. This probably happened because not enough memory could be allocated." result
        |> fail
