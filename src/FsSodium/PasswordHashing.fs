module FsSodium.PasswordHashing

type Salt = private SaltBytes of byte[]
let private saltLength = Interop.crypto_pwhash_saltbytes()
let defaultAlgorithm = Interop.crypto_pwhash_alg_default()

let generateSalt () = Random.bytes saltLength |> SaltBytes

type HashPasswordSettings = {
    NumberOfOperations : int
    Memory : int
    Algorithm : int
    Salt : Salt
}

let hashPassword settings password output =
    let (SaltBytes salt) = settings.Salt
    let result =
        Interop.crypto_pwhash(
            output,
            (int64 <| Array.length output),
            password,
            (int64 <| Array.length password),
            salt,
            (int64 settings.NumberOfOperations),
            settings.Memory,
            settings.Algorithm)
    if result = 0 then Ok () else Error ()
