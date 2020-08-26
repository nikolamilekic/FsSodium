module FsSodium.PasswordHashing

open Milekic.YoLo

module Salt = let length = Interop.crypto_pwhash_saltbytes() |> capToInt
type Salt =
    private | Salt of byte[]
    static member Length = Salt.length
    static member Generate() = Random.bytes Salt.length |> Salt
    static member Validate x = validateArrayLength Salt.length Salt x
    member this.Value = let (Salt x) = this in x

module NumberOfOperations =
    let maximum = Interop.crypto_pwhash_opslimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_opslimit_min() |> capToInt
type NumberOfOperations =
    private | NumberOfOperations of uint64
    static member Validate x =
        validateRange
            NumberOfOperations.minimum
            NumberOfOperations.maximum
            (uint64 >> NumberOfOperations)
            x
    member this.Value = let (NumberOfOperations x) = this in int x

module internal Algorithm =
    let defaultAlgorithmInt = Interop.crypto_pwhash_alg_default()
type AlgorithmCodeValidationError = AlgorithmIsNotSupported
type Algorithm =
    | Default
    static member Validate = function
        | x when x = Algorithm.defaultAlgorithmInt -> Ok Default
        | _ -> Error AlgorithmIsNotSupported
    member this.Value =  match this with
                         | Default -> Algorithm.defaultAlgorithmInt

module MemoryLimit =
    let maximum = Interop.crypto_pwhash_memlimit_max() |> capToInt
    let minimum = Interop.crypto_pwhash_memlimit_min() |> capToInt
type MemoryLimit =
    private | MemoryLimit of uint32
    static member Validate x =
        validateRange
            MemoryLimit.minimum MemoryLimit.maximum (uint32 >> MemoryLimit) x
    member this.Value = let (MemoryLimit x) = this in int x

type HashPasswordParameters = {
    NumberOfOperations : NumberOfOperations
    MemoryLimit : MemoryLimit
    Algorithm : Algorithm
    Salt : Salt
}

module internal KeyLength =
    let maximum = Interop.crypto_pwhash_bytes_max() |> capToInt
    let minimum = Interop.crypto_pwhash_bytes_min() |> capToInt
type KeyLength =
    private | KeyLength of int
    static member Validate x =
        validateRange KeyLength.minimum KeyLength.maximum KeyLength x
    member this.Value = let (KeyLength x) = this in int x

module internal Password =
    let minimumLength = Interop.crypto_pwhash_passwd_min() |> capToInt
    let maximumLength = Interop.crypto_pwhash_passwd_max() |> capToInt
type Password private (secret) =
    inherit Secret(secret)
    static member Validate secret =
        let password = new Password(secret)
        secret
        |> Array.length
        |> validateRange
            Password.minimumLength
            Password.maximumLength
            (fun _ -> password)
        |> Result.either Ok (fun x -> password.Dispose(); Error x)

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
            password.Get,
            (Array.length password.Get |> uint64),
            salt,
            operations,
            memory,
            algorithm.Value)
    if result = 0
    then Ok secret
    else Error <| SodiumError result
