module FsSodium.StreamEncryption

open System
open System.Security.Cryptography
open Milekic.YoLo

let private macLength =
    Interop.crypto_secretstream_xchacha20poly1305_abytes()
let private keyLength = Interop.crypto_secretstream_xchacha20poly1305_keybytes()
let private headerLength = Interop.crypto_secretstream_xchacha20poly1305_headerbytes()
let private notLastTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_message()
let private lastTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_final()

type Key private (key) =
    inherit Secret(key)
    static member GenerateDisposable() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretstream_xchacha20poly1305_keygen(key.Secret)
        key
    static member FromPasswordDisposable(parameters, password) =
        result {
            let! keyLength = PasswordHashing.KeyLength.Create keyLength
            let! key = PasswordHashing.hashPassword keyLength parameters password
            return new Key(key)
        }
        |> Result.failOnError "Password could not be hashed. This should not happen. Please report this error."
type Header = private Header of byte[]
type State =
    private State of Interop.crypto_secretstream_xchacha20poly1305_state
    with
        static member MakeDecryptionState(key : Key, Header header) =
            let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
            let result =
                Interop.crypto_secretstream_xchacha20poly1305_init_pull(
                    &s,
                    header,
                    key.Secret)
            if result = 0 then Ok <| State s else Error ()
        static member MakeEncryptionState(key : Key) =
            let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
            let header = Array.zeroCreate headerLength
            let result =
                Interop.crypto_secretstream_xchacha20poly1305_init_push(
                    &s,
                    header,
                    key.Secret)
            if result = 0
            then Header header, State s
            else CryptographicException("Making encryption state failed. This should not happen. Please report this error.")
                 |> raise

type MessageType = NotLast | Last

let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength
let encryptPartTo (State state) messageType plainText plainTextLength cipherText =
    if Array.length cipherText < getCipherTextLength plainTextLength
    then failwith "Cipher text buffer is not big enough." else

    if Array.length plainText < plainTextLength
    then failwith "Plain text was expected to be larger." else

    let mutable s = state
    let tag = match messageType with
              | NotLast -> notLastTag
              | Last -> lastTag

    let result =
        Interop.crypto_secretstream_xchacha20poly1305_push(
            &s,
            cipherText,
            IntPtr.Zero,
            plainText,
            uint64 plainTextLength,
            null,
            0UL,
            byte tag)

    if result <> 0 then
        CryptographicException("Encryption failed. This should not happen. Please report this error.")
        |> raise
    else State s
let encryptPart state (plainText, messageType)  =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    let nextState =
        encryptPartTo state messageType plainText plainTextLength cipherText
    cipherText, nextState
let decryptPartTo (State state) cipherText cipherTextLength plainText =
    if Array.length plainText < getPlainTextLength cipherTextLength
    then failwith "Plain text buffer is not big enough." else

    if Array.length cipherText < cipherTextLength
    then failwith "Cipher text was expected to be larger." else

    let mutable s = state
    let mutable tag = 0uy

    let result =
        Interop.crypto_secretstream_xchacha20poly1305_pull(
            &s,
            plainText,
            IntPtr.Zero,
            &tag,
            cipherText,
            uint64 cipherTextLength,
            null,
            0UL)

    if result = 0 then
        let tag = match tag with
                  | x when x = notLastTag -> NotLast
                  | x when x = lastTag -> Last
                  | _ -> CryptographicException("Received an unexpected tag")
                         |> raise
        Ok (tag, State s)
    else Error "Decryption failed"
let decryptPart state cipherText =  result {
    let cipherTextLength = Array.length cipherText
    let plainTextLength = getPlainTextLength cipherTextLength
    let plainText = Array.zeroCreate plainTextLength
    let! messageType, nextState =
        decryptPartTo state cipherText cipherTextLength plainText
    return plainText, messageType, nextState
}
