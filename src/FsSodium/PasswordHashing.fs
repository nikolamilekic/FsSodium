module FsSodium.PasswordHashing

open Milekic.YoLo
open Milekic.YoLo.Validation

module Salt = let length = Interop.crypto_pwhash_saltbytes()
type Salt = private Salt of byte[]
    with
        static member Generate() = Random.bytes Salt.length |> Salt
        static member FromBytes x =
            if Array.length x = Salt.length then Salt x |> Some else None
        member this.Bytes = let (Salt x) = this in x

module internal NumberOfOperations =
    let maximum = Interop.crypto_pwhash_opslimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_opslimit_min() |> capToInt
type NumberOfOperations = private NumberOfOperations of uint64
    with
        static member Maximum = NumberOfOperations.maximum
        static member Minimum = NumberOfOperations.minimum
        static member Create = validateRange (uint64 >> NumberOfOperations)
        member this.AsInt = let (NumberOfOperations x) = this in int x

module internal Algorithm =
    let defaultAlgorithmInt = Interop.crypto_pwhash_alg_default()
type Algorithm = Default
    with
        static member FromInt = function
            | x when x = Algorithm.defaultAlgorithmInt -> Some Default
            | _ -> None
        member this.AsInt =  match this with
                             | Default -> Algorithm.defaultAlgorithmInt

module internal MemoryLimit =
    let maximum = Interop.crypto_pwhash_memlimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_memlimit_min() |> capToInt
type MemoryLimit = private MemoryLimit of uint64
    with
        static member Maximum = MemoryLimit.maximum
        static member Minimum = MemoryLimit.minimum
        static member Create = validateRange (uint64 >> MemoryLimit)
        member this.AsInt = let (MemoryLimit x) = this in int x

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
type PasswordValidationError = PasswordIsTooShort | PasswordIsTooLong
type Password private (secret) =
    inherit Secret(secret)
    static member CreateDisposable secret =
        let password = new Password(secret)
        let length = Array.length secret
        if length < Password.minimumLength then Error PasswordIsTooShort
        elif length > Password.maximumLength then Error PasswordIsTooLong
        else Ok password
        |> Result.either Ok (fun x -> password.Dispose(); Error x)

type HashPasswordError = SodiumError of int
let hashPassword
    (KeyLength keyLength)
    {
        Salt = (Salt salt)
        Algorithm = algorithm
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
            algorithm.AsInt)
    if result = 0
    then Ok secret
    else Error <| SodiumError result
