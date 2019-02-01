module FsSodium.PasswordHashing

open System

type Salt = private SaltBytes of byte[]
let private saltLength = Interop.crypto_pwhash_saltbytes()
let defaultAlgorithm = Interop.crypto_pwhash_alg_default()

let generateSalt () = Random.bytes saltLength |> SaltBytes

type HashPasswordParameters = {
    NumberOfOperations : int
    Memory : int
    Algorithm : int
    Salt : Salt
}

let hashPassword keySize parameters password =
    let (SaltBytes salt) = parameters.Salt
    let key = Array.zeroCreate keySize
    let secret = new Secret(key)
    let result =
        Interop.crypto_pwhash(
            key,
            (int64 <| keySize),
            password,
            (int64 <| Array.length password),
            salt,
            (int64 parameters.NumberOfOperations),
            parameters.Memory,
            parameters.Algorithm)
    if result = 0
    then Ok secret
    else (secret :> IDisposable).Dispose(); Error ()
